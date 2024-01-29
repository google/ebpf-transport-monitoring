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

#include "ebpf_monitor/config_manager/proc_manager.h"

#include <errno.h>
#include <unistd.h>
#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_format.h"
#include "absl/time/time.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "ebpf_monitor/utils/proc_reader.h"
#include "ebpf_monitor/ebpf_monitor.h"
#include "ebpf_monitor/utils/event_manager.h"
#include "event2/event.h"

namespace ebpf_monitor {

typedef struct {
  ProcManager * self;
  std::string proc_name;
  pid_t       last_pid;
} __FindPids;

void ProcManager::Init() {
  base_ = EventManager::GetInstance().event_base();
  auto event = event_new(base_, -1, EV_PERSIST,
                         ProcManager::FindNewPids, this);
  auto timeval = absl::ToTimeval(absl::Seconds(10));
  event_add(event, &timeval);
}

void ProcManager::AddProcess(absl::string_view proc_name) {
  if (procs_.find(proc_name) != procs_.end()) {return;}
  auto arg = new __FindPids{this, std::string(proc_name)};
  procs_.insert(std::string(proc_name));
  int error = event_base_once(base_, -1, EV_TIMEOUT,
                              ProcManager::FindAllPids, arg, NULL);
  if (error) {
    std::cerr << "Could not queue event" << std::endl;
  }
}

void ProcManager::FindNewPids(evutil_socket_t, short, void *arg) {  // NOLINT
  ProcManager * self = static_cast<ProcManager *>(arg);
  self->CleanupDeadProcs();
  for (auto it = self->procs_.begin(); it != self->procs_.end(); ++it) {
    auto pids = GetProcesses(*it);
    if (!pids.ok()) {
      std::cerr << pids.status() << std::endl;
      continue;
    }
    self->AddPids(*pids, *it);
  }
}

void ProcManager::RemoveProcess(absl::string_view proc_name){
  procs_.erase(proc_name);
  for (auto it = pids_.cbegin(); it != pids_.cend() ; /* no increment */)
  {
    if (it->second == proc_name) {
      pids_.erase(it++);
      auto status =
          ebpf_monitor::EbpfMonitor::GetInstance().StopMonitoring(it->first);
      if (!status.ok()){
        std::cerr << status << std::endl;
      }
    } else {
      ++it;
    }
  }
}

void ProcManager::AddPids (std::vector<pid_t> pids) {
  for (pid_t pid : pids) {
    pids_.insert({pid, std::string(kUnnamedProcess)});
    auto status = ebpf_monitor::EbpfMonitor::GetInstance().Monitor(pid);
    if (!status.ok()) {
      std::cerr <<  status.message() << std::endl;
    }
  }
}

void ProcManager::AddPids (std::vector<pid_t> pids,
                           absl::string_view proc_name) {
  for (pid_t pid : pids) {
    if (pids_.find(pid) != pids_.end()) {
      continue;
    }
    pids_.insert({pid, std::string(proc_name)});
    auto status = ebpf_monitor::EbpfMonitor::GetInstance().Monitor(pid);
    if (!status.ok()) {
      std::cerr <<  status.message() << std::endl;
    }
  }
}

bool ProcManager::CheckProcess(absl::string_view proc_name) {
  if (procs_.find(proc_name) == procs_.end()) {
    return false;
  }
  return true;
}

void ProcManager::FindAllPids(evutil_socket_t, short, void *arg) { // NOLINT
  __FindPids * ctx = static_cast<__FindPids *>(arg);
  auto it = ctx->self->procs_.find(ctx->proc_name);
  if (it == ctx->self->procs_.end()) {
    return;
  }
  auto pids = GetProcesses(ctx->proc_name);
  if (!pids.ok()) {
    std::cerr << pids.status() << std::endl;
    return;
  }
  ctx->self->AddPids(*pids, ctx->proc_name);
}

void ProcManager::CleanupDeadProcs() {
  for (auto it = this->pids_.begin(); it != this->pids_.end(); ) {
    auto pid = it->first;
    int retVal = getpgid(pid);
    if (retVal != pid) {
      int error = errno;
      if (error == ESRCH) {
        auto status =
            ebpf_monitor::EbpfMonitor::GetInstance().StopMonitoring(pid);
        if (!status.ok()) {
          std::cerr << status << std::endl;
        }
      } else {
        std::cerr <<
          absl::StrFormat("Received error for getpgid (%d): %d\n", pid, error);
      }
      this->pids_.erase(it++);
    } else {
        ++it;
    }
}

  for (const auto& proc : this->pids_) {
    auto pid = proc.first;
    int ret_val = getpgid(pid);
    if (ret_val != pid) {
      int error = errno;
      if (error == ESRCH) {
        auto status =
            ebpf_monitor::EbpfMonitor::GetInstance().StopMonitoring(pid);
        if (!status.ok()) {
          std::cerr << status << std::endl;
        }
      } else {
        std::cerr <<
          absl::StrFormat("Received error for getpgid (%d): %d\n", pid, error);
      }
      this->pids_.erase(pid);
    }
  }
}

}  // namespace ebpf_monitor
