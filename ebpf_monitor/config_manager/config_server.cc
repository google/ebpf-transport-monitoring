// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ebpf_monitor/config_manager/config_server.h"

#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "net_http/public/response_code_enum.h"
#include "net_http/server/public/httpserver.h"
#include "net_http/server/public/httpserver_interface.h"
#include "net_http/server/public/server_request_interface.h"

ABSL_FLAG(uint16_t, server_port, 12000, "config server port");

using net_http::HTTPStatusCode;
using net_http::ServerRequestInterface;

namespace ebpf_monitor {

// All requests should be executed in the same thread
class RequestExecutor final
    : public net_http::EventExecutor {
 public:
  RequestExecutor() = default;
  void Schedule(std::function<void()> fn) override { fn(); }
};

void ConfigServer::ProcessProcNameRequest(ServerRequestInterface* request) {
  absl::string_view type = request->http_method();
  auto content_type = request->GetRequestHeader("content-type");
  if (content_type.empty() || content_type != "text/plain") {
    request->ReplyWithStatus(HTTPStatusCode::BAD_REQUEST);
    return;
  }
  int64_t num_bytes = 0;
  auto body = request->ReadRequestBytes(&num_bytes);
  // Name of process in linux cannot be more than 255 bytes
  if (num_bytes == 0 || num_bytes > 255) {
    net_http::SetContentTypeTEXT(request);
    request->WriteResponseString("Invalid name, expected length less than 256");
    request->ReplyWithStatus(HTTPStatusCode::BAD_REQUEST);
    return;
  }

  if (type == "GET") {
    absl::string_view proc_name = absl::string_view(body.get(), num_bytes);
    net_http::SetContentTypeTEXT(request);
    bool exists = proc_manager_->CheckProcess(proc_name);
    fprintf(stderr, "lightfoot: handle GET request for |%s| exists: %d\n",
            std::string(proc_name.data(), proc_name.length()).c_str(), exists);
    if (exists) {
      request->ReplyWithStatus(HTTPStatusCode::OK);
    } else {
      request->ReplyWithStatus(HTTPStatusCode::NOT_FOUND);
    }
    return;
  }

  if (type == "POST") {
    absl::string_view proc_name = absl::string_view(body.get(), num_bytes);
    fprintf(stderr, "lightfoot: handle POST request for |%s|\n",
            std::string(proc_name.data(), proc_name.length()).c_str());
    proc_manager_->AddProcess(proc_name);
    request->ReplyWithStatus(HTTPStatusCode::OK);
    return;
  }

  net_http::SetContentTypeTEXT(request);
  request->WriteResponseString("Unknown request type");
  request->ReplyWithStatus(HTTPStatusCode::BAD_REQUEST);
}

absl::Status ConfigServer::Start() {
  auto options =
      std::make_unique<net_http::ServerOptions>();
  options->AddPort(absl::GetFlag(FLAGS_server_port));
  options->SetExecutor(std::make_unique<RequestExecutor>());

  auto server = CreateEvHTTPServer(std::move(options));
  http_server_ = std::move(server);

  auto proc_manager = proc_manager_;
  auto proc_handler = [this](ServerRequestInterface* request) {
    this->ProcessProcNameRequest(request);
  };
  net_http::RequestHandlerOptions handler_options;
  http_server_->RegisterRequestHandler("/proc-name", proc_handler,
                                       handler_options);

  // Blocking here with the use of RequestExecutor
  http_server_->StartAcceptingRequests();
  return absl::OkStatus();
}
absl::Status ConfigServer::Stop() { return absl::OkStatus(); }

}  // namespace ebpf_monitor
