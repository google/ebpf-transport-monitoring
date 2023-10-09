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

#ifndef _EBPF_MONITOR_UTILS_DWARF_READER_H_
#define _EBPF_MONITOR_UTILS_DWARF_READER_H_

#include <cstddef>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "elfutils/libdw.h"
#include "ebpf_monitor/utils/sym_addrs.h"
#include "ebpf_monitor/utils/utils.h"

namespace ebpf_monitor {

class DwarfReader {
 public:
  explicit DwarfReader(std::string path);
  absl::Status FindStructs(
      const absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
          variables);
  absl::StatusOr<member_var_t> GetMemberVar(absl::string_view struct_name,
                                            absl::string_view member_name);
  absl::StatusOr<SourceLanguage> GetSourceLanguage();
 private:
  bool CheckDie(
      Dwarf_Die* die,
      const absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
          variables,
      size_t& count);
  void TraverseDie(
      Dwarf_Die* die,
      const absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
          variables,
      size_t& count);
  absl::flat_hash_map<std::string,
                      absl::flat_hash_map<std::string, member_var_t> >
      structs_;
  const std::string binary_path_;
};

}  // namespace ebpf_monitor
#endif  // _EBPF_MONITOR_UTILS_DWARF_READER_H_
