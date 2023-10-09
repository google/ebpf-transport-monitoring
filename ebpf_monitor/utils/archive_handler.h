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

#ifndef _EBPF_MONITOR_UTILS_ARCHIVE_HANDLER_H_
#define _EBPF_MONITOR_UTILS_ARCHIVE_HANDLER_H_

#include <string>

#include "absl/status/status.h"
#include "archive.h"

namespace ebpf_monitor {

/* Files that will be used by the monitor will be linked to the binary as a
  .o file. This class inflates, reads this archive and writes files specified
  to disk. It is important to call finish to free memory used. */
class ArchiveHandler {
 public:
  ArchiveHandler() = delete;
  ArchiveHandler(const void* buf, uint64_t size);
  absl::Status Init();
  absl::Status WriteFileToDisk(std::string file_name, std::string dest_path);
  absl::Status WriteAllToDisk(std::string dest_path);
  void Finish();
  ~ArchiveHandler();

 private:
  const void* buf_;
  uint64_t size_;
  struct archive* archive_;
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_UTILS_ARCHIVE_HANDLER_H_
