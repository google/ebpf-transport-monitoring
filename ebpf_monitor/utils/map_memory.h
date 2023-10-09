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

#ifndef _EBPF_MONITOR_UTILS_MAP_MEMORY_H_
#define _EBPF_MONITOR_UTILS_MAP_MEMORY_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"

namespace ebpf_monitor {

class MapMemory {
 public:
  static MapMemory& GetInstance() {
    static MapMemory instance;
    return instance;
  }

  absl::Status StoreMap(const std::string& map_name, int value) {
    if (mem_.find(map_name) != mem_.end()) {
      return absl::AlreadyExistsError(
          absl::StrFormat("map with name %s", map_name));
    }
    mem_[map_name] = value;
    return absl::OkStatus();
  }

  absl::StatusOr<int> GetMap(const std::string& map_name) {
    if (mem_.find(map_name) == mem_.end()) {
      return absl::NotFoundError(absl::StrFormat("map with %s", map_name));
    }
    return mem_[map_name];
  }

 private:
  MapMemory() = default;
  ~MapMemory() = default;
  MapMemory(const MapMemory&) = delete;
  MapMemory& operator=(const MapMemory&) = delete;

  absl::flat_hash_map<std::string, int> mem_;
};

}  // namespace ebpf_monitor

#endif
