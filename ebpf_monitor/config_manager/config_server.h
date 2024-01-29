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
#include "absl/status/status.h"

#include "ebpf_monitor/config_manager/proc_manager.h"
#include "net_http/server/public/httpserver_interface.h"

#include <memory>

using net_http::HTTPServerInterface;
using net_http::ServerRequestInterface;


namespace ebpf_monitor {

class ConfigServer {
 public:
  ConfigServer() = delete;
  ConfigServer(std::shared_ptr<ProcManager> proc_manager) :
    proc_manager_(proc_manager) {}
  absl::Status Start();
  absl::Status Stop();
 private:
  void ProcessProcNameRequest(ServerRequestInterface* request);
  std::unique_ptr<HTTPServerInterface> http_server_;
  std::shared_ptr<ProcManager> proc_manager_;
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_CONFIG_MANAGER_CONFIG_SERVER_H_
