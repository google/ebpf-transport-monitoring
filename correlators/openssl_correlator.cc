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

#include "correlators/openssl_correlator.h"

#include <cstdlib>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "sources/common/correlator_types.h"


namespace ebpf_monitor {

#define PERF_PAGES 2

static uint32_t rand32()
{
  return ((rand() & 0x3) << 30) | ((rand() & 0x7fff) << 15) | (rand() & 0x7fff);
}

std::string gen_uuid4()
{
    return absl::StrFormat("%08x-%04x-%04x-%04x-%04x%08x",
        rand32(),
        rand32() & 0xffff,
        ((rand32() & 0x0fff) | 0x4000),
        (rand32() & 0x3fff) + 0x8000,
        rand32() & 0xffff, rand32());
}

absl::Status OpenSslCorrelator::Init() {
  auto it = sources_.find(Layer::kHTTP2);
  if (it == sources_.end()) {
    return absl::NotFoundError("No Http sources found");
  }
  for (auto &source : it->second) {
    auto map = source->GetMap("openssl_correlation_events");
    if (!map.ok()) {
      return map.status();
    }
    log_sources_.push_back(*map);
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> OpenSslCorrelator::GetUUID(uint64_t eBPF_conn_id) {
  auto it = connection_map_.find(eBPF_conn_id);
  if (it == connection_map_.end()) {
    return absl::NotFoundError("conn id not registered");
  }
  return connection_map_[eBPF_conn_id];
}

std::vector<std::shared_ptr<DataCtx>> &OpenSslCorrelator::GetLogSources() {
  return log_sources_;
}

std::vector<std::shared_ptr<DataCtx>> &OpenSslCorrelator::GetMetricSources() {
  return metric_sources_;
}

bool OpenSslCorrelator::CheckUUID(std::string uuid) {
  for (const auto& pair : connection_map_) {
    if (pair.second == uuid) {
      return true;
    }
  }
  return false;
}

absl::Status OpenSslCorrelator::HandleOpenssl(void * data) {
  const openssl_correlation *const c_data =
      static_cast<const openssl_correlation *const>(data);
  if (c_data->mdata.type == kSslNewConnection){
    auto uuid = gen_uuid4();
    struct ConnInfo conn_info = {0};
    connection_map_[c_data->mdata.conn_id] = gen_uuid4();
    conn_info.UUID = uuid;
    conn_info.h2_conn_id = c_data->mdata.conn_id;
    correlator_[uuid] = conn_info;
    std::cout << uuid << "\n";
  }
  return absl::OkStatus();
}

absl::Status OpenSslCorrelator::HandleData(absl::string_view log_name,
                                        void * data,
                                        uint32_t size) {
  if (!log_name.compare("openssl_correlation_events")) {
    return HandleOpenssl(data);
  }
  return absl::OkStatus();
}


}  // namespace ebpf_monitor
