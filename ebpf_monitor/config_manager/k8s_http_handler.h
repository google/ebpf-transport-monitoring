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

#ifndef _EBPF_MONITOR_CONFIG_MANAGER_K8S_MANAGER_H_
#define _EBPF_MONITOR_CONFIG_MANAGER_K8S_MANAGER_H_

#include <memory>
#include <string>
#include "absl/status/status.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "ebpf_monitor/config_manager/proc_manager.h"
#include "event2/event.h"
#include "ebpf_monitor/config_manager/config_server.h"


namespace ebpf_monitor {

class K8sHttpHandler {
 public:
  K8sHttpHandler(ConfigServer* server, ProcManager* proc_manager);
  absl::Status AddContainer(std::string cri,
                            std::string container_id);
 private:
  void ProcessCriRequest(ServerRequestInterface* request);
  static void FindPids(evutil_socket_t, short, void *arg);  // NOLINT
  absl::flat_hash_map<std::string, std::string> containers_;
  ProcManager* proc_manager_;
  struct event_base *base_;
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_CONFIG_MANAGER_K8S_MANAGER_H_
