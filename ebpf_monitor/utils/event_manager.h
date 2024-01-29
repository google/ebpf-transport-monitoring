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

#ifndef _EBPF_MONITOR_UTILS_EVENT_MANAGER_H_
#define _EBPF_MONITOR_UTILS_EVENT_MANAGER_H_

#include "absl/status/status.h"
#include "event2/event.h"
#include "event2/thread.h"

namespace ebpf_monitor {

class EventManager{
 public:
  static EventManager& GetInstance() {
    static EventManager instance;
    return instance;
  }
  absl::Status Init() {
    if (evthread_use_pthreads() != 0) {
      return absl::InternalError("events with threading not supported.");
    }
    return absl::OkStatus();
  }

  void Start() {
    event_base_dispatch(base_);
  }
  struct event_base *event_base() { return base_; }

 private:
  EventManager(): base_(event_base_new()) {}
  struct event_base *base_;
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_EVENT_MANAGER_H_
