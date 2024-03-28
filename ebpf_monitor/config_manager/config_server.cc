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
#include "net_http/server/public/httpserver.h"
#include "net_http/server/public/httpserver_interface.h"
#include "net_http/server/public/server_request_interface.h"

namespace ebpf_monitor {

// All requests should be executed in the same thread
class RequestExecutor final
    : public net_http::EventExecutor {
 public:
  RequestExecutor() = default;
  void Schedule(std::function<void()> fn) override { fn(); }
};

void ConfigServer::AddRequestHandler(absl::string_view request_path,
                                     RequestHandler request_handler) {
  net_http::RequestHandlerOptions handler_options;
  http_server_->RegisterRequestHandler(request_path, request_handler,
                                       handler_options);
}

void ConfigServer::Init () {
  auto options =
      std::make_unique<net_http::ServerOptions>();
  options->AddPort(port_);
  options->SetExecutor(std::make_unique<RequestExecutor>());
  auto server = CreateEvHTTPServer(std::move(options));
  http_server_ = std::move(server);
}

absl::Status ConfigServer::Start() {
  bool status = http_server_->StartAcceptingRequests();
  if (!status) {
    return absl::InternalError("Failed to start server");
  }
  return absl::OkStatus();
}

void ConfigServer::Stop() {
  http_server_->Terminate();
  http_server_->WaitForTermination();
}

}  // namespace ebpf_monitor
