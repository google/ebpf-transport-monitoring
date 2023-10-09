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

#ifndef _SOURCES_OPENSSL_SOURCE_H_
#define _SOURCES_OPENSSL_SOURCE_H_

#include <string>

#include "ebpf_monitor/source/source.h"
#include "ebpf_monitor/utils/elf_reader.h"

namespace ebpf_monitor {

/*
 * In the first revision we will only trace when OpenSSL or BoringSSL is linked
 * statically.
 */
class OpenSslSource : public Source {
 public:
  OpenSslSource();
  absl::Status AddPID(uint64_t pid);
  ~OpenSslSource() override;
  std::string ToString() const override { return "OpenSslSource"; };

 private:
  absl::Status RegisterProbes(ElfReader* elf_reader, std::string& path,
                              uint64_t pid);
};

}  // namespace ebpf_monitor

#endif  // _SOURCES_OPENSSL_SOURCE_H_
