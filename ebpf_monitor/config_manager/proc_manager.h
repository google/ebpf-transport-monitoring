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

#ifndef _EBPF_MONITOR_PID_MANAGER_PROC_MANAGER_H_
#define _EBPF_MONITOR_PID_MANAGER_PROC_MANAGER_H_

#include <string>
#include <vector>

#include "event2/event.h"
#include "absl/strings/string_view.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"

namespace ebpf_monitor {

/* In case we are given specific pids to trace then we will save their name as the
* kUnnamedProcess so as seperate them from processes who's names we are tracing.*/
constexpr absl::string_view kUnnamedProcess = "__Unnamed__";
/* This class accepts process names from config server, finds and tracks all
 * pids. It can also accept pids from the command line.
 * 
 * We will also use eBPF to keep track of all processes created to make sure we
 * are able to trace a process as early as possible.
 */
class ProcManager {
 public:
  ProcManager() = default;
  void Init();
  void AddProcess(absl::string_view proc_name);
  void RemoveProcess(absl::string_view proc_name);
  void AddPids (std::vector<pid_t> pids);
  bool CheckProcess(absl::string_view proc_name);
 private:
  static void FindAllPids(evutil_socket_t, short, void *arg);  // NOLINT
  static void FindNewPids(evutil_socket_t, short, void *arg);  // NOLINT
  void AddPids (std::vector<pid_t> pids, absl::string_view proc_name);
  void CleanupDeadProcs();
  /* This map stores the name of the processes, but the value is the last pid
  that it searched, in the search for new processes with the name.*/
  absl::flat_hash_set<std::string> procs_;
  absl::flat_hash_map<pid_t, std::string> pids_;
  struct event_base *base_;
};

}


#endif  // _EBPF_MONITOR_PID_MANAGER_PROC_MANAGER_H_
