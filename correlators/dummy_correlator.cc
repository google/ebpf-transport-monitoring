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

#include "correlators/dummy_correlator.h"

#include <cstdlib>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"

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

absl::Status DummyCorrelator::Init() {
  srand(time(NULL));
  return absl::OkStatus();
}

absl::StatusOr<std::string> DummyCorrelator::GetUUID(uint64_t eBPF_conn_id) {
  auto it = connection_map_.find(eBPF_conn_id);
  if (it == connection_map_.end()) {
    connection_map_[eBPF_conn_id] = gen_uuid4();
  }
  return connection_map_[eBPF_conn_id];
}

std::vector<std::shared_ptr<DataCtx>> &DummyCorrelator::GetLogSources() {
  return log_sources_;
}

std::vector<std::shared_ptr<DataCtx>> &DummyCorrelator::GetMetricSources() {
  return metric_sources_;
}

bool DummyCorrelator::CheckUUID(std::string uuid) {
  for (const auto& pair : connection_map_) {
    if (pair.second == uuid) {
      return true;
    }
  }
  return false;
}

}  // namespace ebpf_monitor
