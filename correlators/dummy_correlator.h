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

#ifndef _CORRELATORS_DUMMY_CORRELATOR_
#define _CORRELATORS_DUMMY_CORRELATOR_


#include <memory>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "ebpf_monitor/correlator/correlator.h"

namespace ebpf_monitor {

class DummyCorrelator : public CorrelatorInterface {
 public:
  DummyCorrelator() = default;
  ~DummyCorrelator() = default;
  absl::Status Init() override;
  absl::StatusOr<std::string> GetUUID(uint64_t eBPF_conn_id) override;
  std::vector<std::shared_ptr<DataCtx> >& GetLogSources() override;
  std::vector<std::shared_ptr<DataCtx> >& GetMetricSources() override;
  absl::flat_hash_map<std::string, std::string> GetLabels(
      std::string uuid) override {return {}; };
  std::vector<std::string> GetLabelKeys() override {return {}; };

 private:
  absl::Status HandleData(absl::string_view log_name,  void*  data,
                           uint32_t size) override {return absl::OkStatus();};
  absl::Status HandleData(absl::string_view  metric_name, void* key,
                          void* value) override {return absl::OkStatus();};
  bool CheckUUID(std::string uuid) override;
  void Cleanup() override{};

  std::vector<std::shared_ptr<DataCtx> > log_sources_;
  std::vector<std::shared_ptr<DataCtx> > metric_sources_;
};

}  // namespace ebpf_monitor

#endif
