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

#ifndef _CORRELATORS_OPENSSL_CORRELATOR_H_
#define _CORRELATORS_OPENSSL_CORRELATOR_H_

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

#include "ebpf_monitor/source/data_ctx.h"
#include "ebpf_monitor/correlator/correlator.h"

namespace ebpf_monitor {

class OpenSslCorrelator final : public CorrelatorInterface {
 public:
  OpenSslCorrelator() = default;
  ~OpenSslCorrelator() = default;
  absl::Status Init() override;
  absl::StatusOr<std::string> GetUUID(uint64_t eBPF_conn_id) override;
  std::vector<std::shared_ptr<DataCtx> >& GetLogSources() override;
  std::vector<std::shared_ptr<DataCtx> >& GetMetricSources() override;
  absl::flat_hash_map<std::string, std::string> GetLabels(
      std::string uuid) override {return {}; };
  std::vector<std::string> GetLabelKeys() override {return {};};

 private:
  struct ConnInfo {
    uint64_t pid;
    uint64_t h2_conn_id;
    uint64_t tcp_conn_id;
    std::string UUID;
  };
  absl::Status HandleData(absl::string_view log_name,  void*  data,
                           uint32_t size) override;
  absl::Status HandleData(absl::string_view  metric_name, void* key,
                          void* value) override {return absl::OkStatus();};
  absl::Status HandleOpenssl(void * data);
  bool CheckUUID(std::string uuid) override;
  void Cleanup() override {};

  std::vector<std::shared_ptr<DataCtx> > log_sources_;
  std::vector<std::shared_ptr<DataCtx> > metric_sources_;
  absl::flat_hash_map<std::string, struct ConnInfo> correlator_;
};

}  // namespace ebpf_monitor


#endif  // _CORRELATORS_OPENSSL_CORRELATOR_H_
