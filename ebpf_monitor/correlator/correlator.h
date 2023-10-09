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

#ifndef _EBPF_MONITOR_CORRELATOR_H_
#define _EBPF_MONITOR_CORRELATOR_H_

#include <vector>

#include "absl/container/flat_hash_map.h"
#include "ebpf_monitor/exporter/handlers.h"
#include "ebpf_monitor/source/source.h"
#include "ebpf_monitor/source/data_ctx.h"


namespace ebpf_monitor {

enum class Layer { kHTTP2, kTCP, kTLS };

class CorrelatorInterface : public LogHandlerInterface,
                            public MetricHandlerInterface {
 public:
  void AddSource(Layer layer, std::shared_ptr <Source> source) {
    sources_[layer].push_back(source);
  }

  virtual absl::StatusOr<std::string> GetUUID(uint64_t eBPF_conn_id) = 0;

  virtual bool CheckUUID(std::string uuid) = 0;
  virtual absl::flat_hash_map<std::string, std::string> GetLabels(
      std::string uuid) = 0;
  virtual std::vector<std::string> GetLabelKeys() = 0;

  virtual std::vector<std::shared_ptr<DataCtx>> &GetLogSources() = 0;
  virtual std::vector<std::shared_ptr<DataCtx>> &GetMetricSources() = 0;
  virtual absl::Status Init() = 0;

 protected:
  absl::flat_hash_map<Layer, std::vector<std::shared_ptr <Source>>> sources_;
  absl::flat_hash_map<uint64_t, std::string> connection_map_;
};

}  // namespace ebpf_monitor
#endif  // _EBPF_MONITOR_CORRELATOR_H_
