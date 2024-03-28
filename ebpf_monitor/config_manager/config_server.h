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

#ifndef _EBPF_MONITOR_CONFIG_MANAGER_CONFIG_SERVER_H_
#define _EBPF_MONITOR_CONFIG_MANAGER_CONFIG_SERVER_H_

#include <memory>
#include <stdint.h>
#include <sys/types.h>
#include "absl/flags/flag.h"
#include "absl/strings/string_view.h"
#include "absl/status/status.h"

#include "net_http/server/public/httpserver_interface.h"

using net_http::HTTPServerInterface;
using net_http::ServerRequestInterface;
using net_http::RequestHandler;

namespace ebpf_monitor {

class ConfigServer {
 public:
  ConfigServer(uint16_t port) :port_(port) {}
  void Init();
  void AddRequestHandler (absl::string_view request_path,
                          RequestHandler request_handler);
  absl::Status Start();
  void Stop();
 private:
  void ProcessProcNameRequest(ServerRequestInterface* request);
  void ProcessCrioRequest(ServerRequestInterface* request);
  std::unique_ptr<HTTPServerInterface> http_server_;
  uint16_t port_;
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_CONFIG_MANAGER_CONFIG_SERVER_H_
