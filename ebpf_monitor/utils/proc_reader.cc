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

#include "ebpf_monitor/utils/proc_reader.h"

#include <fcntl.h> /* Definition of AT_* constants */
#include <linux/limits.h>
#include <unistd.h>

#include <fstream>
#include <ios>
#include <iostream>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"

namespace {

absl::StatusOr<std::string> ReadLink(const std::string& link) {
  char buffer[PATH_MAX + 1];
  int dirfd = AT_FDCWD;
  auto bytes = ::readlinkat(dirfd, link.c_str(), &buffer[0], sizeof(buffer));
  if (bytes == -1) {
    return absl::InternalError("Failed to readlinkat");
  }
  return std::string(buffer, bytes);
}

absl::StatusOr<std::string> GetExe(std::string& task_root) {
  static const std::string EXE_FILE("exe");
  auto path = task_root + EXE_FILE;
  return ReadLink(path);
}

absl::StatusOr<std::string> GetEnvironValue(absl::string_view task_root,
                                            absl::string_view key) {
  static const std::string KEnvironFile("environ");
  auto path = absl::StrCat(task_root, KEnvironFile);
  std::ifstream ifs;
  ifs.open(std::string(task_root), std::ios::in);
  std::string token;
  while (std::getline(ifs, token, '\0').good()) {
    std::vector<absl::string_view> parts =
        absl::StrSplit(token, absl::MaxSplits('=', 1));
    if (parts.size() == 2 && parts[0] == key) {
      return std::string(parts[1]);
    }
  }
  return absl::NotFoundError("Could Not find key");
}
}  // namespace

namespace ebpf_monitor {

absl::StatusOr<std::string> GetBinaryPath(pid_t pid) {
  std::string task_root = absl::StrFormat("/proc/%s/", std::to_string(pid));
  auto exe = GetExe(task_root);
  if (!exe.ok()) {
    return absl::NotFoundError("Cound not find path to executable");
  }
  if (exe->at(0) == '/') {
    return exe;
  }
  auto pwd = GetEnvironValue(task_root, "PWD");
  if (!pwd.ok()) {
    return pwd;
  }
  return absl::StrCat(*pwd, "/", *exe);
}

}  // namespace ebpf_monitor
