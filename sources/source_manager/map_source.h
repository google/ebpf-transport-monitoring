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

#ifndef _SOURCES_SOURCE_MANAGER_SOURCES_MAP_SOURCE_H_
#define _SOURCES_SOURCE_MANAGER_SOURCES_MAP_SOURCE_H_

#include <string>

#include "ebpf_monitor/source/source.h"

namespace ebpf_monitor {

class MapSource : public Source {
 public:
  MapSource();
  ~MapSource() override;
  absl::Status LoadMaps() override;
  std::string ToString() const override { return "MapSource"; };
};

}  // namespace ebpf_monitor

#endif  // _SOURCES_SOURCE_MANAGER_SOURCES_MAP_SOURCE_H_
