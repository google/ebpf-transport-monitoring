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

#ifndef _SOURCES_SOURCE_MANAGER_H2_GO_GRPC_SOURCE_H_
#define _SOURCES_SOURCE_MANAGER_H2_GO_GRPC_SOURCE_H_

#include <sys/types.h>
#include <string>
#include <cstdint>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "sources/common/h2_symaddrs.h"
#include "ebpf_monitor/source/source.h"
#include "ebpf_monitor/utils/elf_reader.h"

namespace ebpf_monitor {
class H2GoGrpcSource : public Source {
 public:
  H2GoGrpcSource();
  absl::Status AddPID(pid_t pid) override;
  absl::Status RemovePID(pid_t pid) override;

  ~H2GoGrpcSource() override;
  std::string ToString() const override { return "H2GoGrpcSource"; };

 private:
  absl::Status CreateProbes(ElfReader* elf_reader,
                            std::string& path,
                            absl::flat_hash_set<std::string>& functions,
                            const char* probe_func);
  absl::Status RegisterProbes(ElfReader* elf_reader, std::string& path,
                              uint64_t pid);
  absl::Status AddCfg(uint64_t pid);
  absl::flat_hash_map<uint64_t, h2_cfg_t> bpf_cfg_;
  absl::flat_hash_map<std::string, std::vector<pid_t>> pid_path_map_;
};

}  // namespace ebpf_monitor

#endif  // _SOURCES_SOURCE_MANAGER_H2_GO_GRPC_SOURCE_H_
