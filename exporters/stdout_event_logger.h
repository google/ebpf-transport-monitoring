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

#ifndef _EBPF_MONITOR__STDOUT_EVENT_LOGGER_H_
#define _EBPF_MONITOR__STDOUT_EVENT_LOGGER_H_

#include <string>
#include <unordered_map>

#include "absl/container/flat_hash_map.h"
#include "ebpf_monitor/exporter/log_exporter.h"

namespace ebpf_monitor {

class StdoutEventExporter : public LogExporterInterface {
 public:
  StdoutEventExporter() = default;
  ~StdoutEventExporter() override = default;
  absl::Status Init() override { return absl::OkStatus(); }

  absl::Status RegisterLog(std::string name, LogDesc& log_desc) override;
  absl::Status HandleData(absl::string_view log_name, void* data,
                          uint32_t size) override;

 private:
  absl::flat_hash_map<std::string, bool> logs_;
};

}  // namespace prober

#endif  // _EBPF_MONITOR__STDOUT_EVENT_LOGGER_H_
