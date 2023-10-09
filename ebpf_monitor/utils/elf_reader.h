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

#ifndef _EBPF_MONITOR_UTILS_ELF_READER_H_
#define _EBPF_MONITOR_UTILS_ELF_READER_H_

#include <cstdint>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "libelf.h"

namespace ebpf_monitor {

struct section_data {
  uint64_t offset;
  uint64_t addr;
};

class ElfReader {
 public:
  typedef enum {
    kValue,
    kOffset,
  } SearchType;

  explicit ElfReader(std::string path);
  // The following two functions work in unison. This is done because searching
  // through the elf file can be a costly operation. Find Symbols creates an
  // internal maps with the offsets found. You can get the offsets at a later
  // time by using GetSymbol.
  absl::Status FindSymbols(const absl::flat_hash_set<std::string>& symbols,
                          SearchType type);
  absl::StatusOr<uint64_t> GetSymbol(absl::string_view symbol);
  absl::Status GetSectionOffset(const char* section_name,
                                struct section_data* data);
  absl::Status ReadData(const char* section_name, uint64_t offset, char* buffer,
                        uint32_t size);
  static absl::StatusOr<uint32_t> GetKernelVersion();

 private:
  absl::StatusOr<int> CheckSection(
    Elf *e, Elf_Scn *section,
    const absl::flat_hash_set<std::string> &symbols, SearchType type);
  const std::string binary_path_;
  absl::flat_hash_map<std::string, struct section_data> section_offsets_;
  absl::flat_hash_map<std::string, uint64_t> symbols_;
};

}  // namespace ebpf_monitor
#endif  // _EBPF_MONITOR_UTILS_ELF_READER_H_
