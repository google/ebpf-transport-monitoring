#include "ebpf_monitor/config_manager/proc_http_handler.h"

#include <string>
#include <cstdint>

#include "absl/log/log.h"
#include "absl/strings/str_format.h"
#include "ebpf_monitor/config_manager/config_server.h"
#include "ebpf_monitor/config_manager/proc_manager.h"
#include "net_http/server/public/server_request_interface.h"
#include "net_http/public/response_code_enum.h"
#include "absl/strings/string_view.h"

using net_http::ServerRequestInterface;
using net_http::HTTPStatusCode;

namespace ebpf_monitor {

ProcHttpHandler::ProcHttpHandler(ConfigServer* server,
                                 ProcManager* proc_manager):
  proc_manager_(proc_manager) {
  auto handler = [this](ServerRequestInterface* request) {
    ProcessProcNameRequest(request);
  };
  server->AddRequestHandler("/proc-name", handler);
}

void ProcHttpHandler::ProcessProcNameRequest(ServerRequestInterface* request) {
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
    LOG(INFO) <<
        absl::StrFormat("lightfoot: handle GET request for |%s| exists: %d\n",
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
    LOG(INFO) <<
        absl::StrFormat("lightfoot: handle POST request for |%s|\n",
            std::string(proc_name.data(), proc_name.length()).c_str());
    proc_manager_->AddProcessAsync(proc_name);
    request->ReplyWithStatus(HTTPStatusCode::OK);
    return;
  }

  net_http::SetContentTypeTEXT(request);
  request->WriteResponseString("Unknown request type");
  request->ReplyWithStatus(HTTPStatusCode::BAD_REQUEST);
}

}