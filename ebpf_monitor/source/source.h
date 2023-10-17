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

#ifndef _EBPF_MONITOR_SOURCE_DATA_SOURCE_H_
#define _EBPF_MONITOR_SOURCE_DATA_SOURCE_H_

#include <string>
#include <vector>
#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "ebpf_monitor/source/data_ctx.h"
#include "ebpf_monitor/source/probes.h"
#include "bpf/libbpf.h"

namespace ebpf_monitor {

// TODO: Convert implementation to an interface rather than
// implementation
class Source {
 public:
  Source() = default;
  Source(std::vector<std::shared_ptr<Probe>> probes,
         std::vector<std::shared_ptr<DataCtx>> log_sources,
         std::vector<std::shared_ptr<DataCtx>> metric_sources,
         absl::string_view file_name, absl::string_view file_name_core,
         absl::string_view pid_filter_map);
  virtual absl::Status Init(bool extract_source);
  virtual absl::Status LoadObj();
  virtual absl::Status LoadMaps();
  virtual absl::Status LoadProbes();
  virtual std::vector<std::shared_ptr<DataCtx>> &GetLogSources();
  virtual std::vector<std::shared_ptr<DataCtx>> &GetMetricSources();
  virtual absl::Status AttachProbe(absl::string_view probe_name);
  virtual absl::Status DetachProbe(absl::string_view probe_name);
  virtual absl::StatusOr<std::shared_ptr<DataCtx>> GetMap(
      absl::string_view map_name);
  virtual absl::Status AddPID(pid_t pid);
  virtual absl::Status RemovePID(pid_t pid);
  virtual std::string ToString() const = 0;
  virtual ~Source() = default;

 protected:
  std::string file_name_;
  std::string file_name_core_;
  struct bpf_object *obj_;
  std::vector<std::shared_ptr<Probe>> probes_;
  std::vector<std::shared_ptr<DataCtx>> log_sources_;
  std::vector<std::shared_ptr<DataCtx>> metric_sources_;
  std::string pid_filter_map_;
  void Cleanup();
  bool init_;

 private:
  absl::Status ShareMaps();
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_SOURCE_DATA_SOURCE_H_
