// Copyright 2023 Google LLC
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

#ifndef _EBPF_MONITOR_UTILS_PROC_READER_H_
#define _EBPF_MONITOR_UTILS_PROC_READER_H_

#include <sys/types.h>

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace ebpf_monitor {

absl::StatusOr<std::string> GetBinaryPath(pid_t pid);
absl::StatusOr<std::vector<pid_t>> GetProcesses(std::string proc_name);

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_UTILS_PROC_READER_H_
