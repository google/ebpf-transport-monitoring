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

#include "ebpf_monitor/utils/os_helper.h"

#include <sys/utsname.h>

#include <cstdio>
#include <fstream>
#include <ios>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "re2/re2.h"

namespace ebpf_monitor {

static void remove_quotes(std::string& input) {
  std::size_t pos = input.find('"');
  while (pos != std::string::npos) {
    input.erase(pos, 1);
    pos = input.find('"', pos);
  }
}

absl::Status OsHelper::CaptureOsInfo() {
  struct utsname u;
  if (uname(&u) == -1) {
    return absl::InternalError("Could not get uname");
  }
  release_ = std::string(u.release);
  arch_ = std::string(u.machine);
  std::ifstream file("/etc/os-release", std::ios::in);
  if (!file.is_open()) {
    return absl::InternalError("Could not open release file");
  }
  RE2 id_pattern("^ID=(.*)");
  RE2 version_pattern("^VERSION_ID=(.*)");
  std::string line;
  while (getline(file, line)) {
    std::string match;
    if (RE2::FullMatch(line, id_pattern, &match)) {
      remove_quotes(match);
      id_ = match;
    }
    if (RE2::FullMatch(line, version_pattern, &match)) {
      remove_quotes(match);
      version_ = match;
    }
  }
  if (version_.empty() || id_.empty()) {
    return absl::InternalError("Could not find Id and version");
  }
  init_ = true;
  file.close();
  return absl::OkStatus();
}

absl::StatusOr<std::string> OsHelper::GetBtfArchivePath() {
  if (!init_) {
    return absl::InternalError("Uninitialized");
  }
  return absl::StrFormat("./%s/%s/%s/%s.btf", id_, version_, arch_, release_);
}

}  // namespace ebpf_monitor
