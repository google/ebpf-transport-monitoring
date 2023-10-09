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

#ifndef _EBPF_MONITOR_UTIL_H_
#define _EBPF_MONITOR_UTIL_H_

#include <cstdint>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "ebpf_monitor/exporter/data_types.h"

namespace ebpf_monitor {

absl::StatusOr<std::string> GetLogString(absl::string_view log_name,
                                                absl::string_view uuid,
                                                const void* const data);
uint64_t GetLogConnId(absl::string_view log_name,
                              const void* const data);
absl::StatusOr<std::string> GetMetricString(absl::string_view name,
                                                    absl::string_view uuid,
                                                    const MetricDesc& desc,
                                                    const void* const key,
                                                    const void* const value,
                                                    uint64_t timestamp);
absl::Time GetLogTime(absl::string_view log_name,
                              const void* const data);
absl::Time GetTimeFromBPFns(uint64_t timestamp);
int64_t GetMetric(const void* const data, MetricType type);


class MetricTimeChecker {
 public:
  MetricTimeChecker() = default;
  // The Checker returns the last metric timestamp or error
  absl::StatusOr<uint64_t> CheckMetricTime(absl::string_view metric_name,
                                           absl::string_view uuid,
                                           uint64_t timestamp);
  absl::StatusOr<uint64_t> GetMetricStartTime(absl::string_view metric_name,
                                              absl::string_view uuid);
  absl::StatusOr<uint64_t> GetMetricTime(absl::string_view metric_name,
                                         absl::string_view uuid);
  absl::flat_hash_set<std::string> GetUUID();
  void DeleteValue(absl::string_view uuid);

 private:
  absl::flat_hash_map<std::string, absl::flat_hash_map<std::string, uint64_t> >
      last_read_;
  absl::flat_hash_map<std::string, absl::flat_hash_map<std::string, uint64_t> >
      start_read_;
  absl::flat_hash_set<std::string> uuids_;
};

class MetricDataMemory {
 public:
  MetricDataMemory() = default;
  // The Checker returns the last metric timestamp or error
  uint64_t StoreAndGetValue(absl::string_view metric_name,
                            absl::string_view uuid,
                            uint64_t data);
  absl::flat_hash_set<std::string> GetUUID();
  void DeleteValue(absl::string_view uuid);

 private:
  absl::flat_hash_map<std::string, absl::flat_hash_map<std::string, uint64_t> >
      data_memory_;
  absl::flat_hash_set<std::string> uuids_;
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_UTIL_H_
