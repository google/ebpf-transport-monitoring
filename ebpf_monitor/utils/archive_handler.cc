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

#include "ebpf_monitor/utils/archive_handler.h"

#include <fstream>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "archive.h"
#include "archive_entry.h"

namespace ebpf_monitor {
ArchiveHandler::ArchiveHandler(const void* buf, uint64_t size)
    : buf_(buf), size_(size), archive_(nullptr) {
}

absl::Status ArchiveHandler::Init() {
  archive_ = archive_read_new();
  archive_read_support_filter_gzip(archive_);
  archive_read_support_format_tar(archive_);
  int status = archive_read_open_memory(archive_, buf_, size_);
  if (status != ARCHIVE_OK) {
    return absl::InternalError(
        absl::StrFormat("libarchive: %s", archive_error_string(archive_)));
  }
  return absl::OkStatus();
}

absl::Status ArchiveHandler::WriteFileToDisk(std::string file_name,
                                             std::string dest_path) {
  if (archive_ == nullptr){
    absl::Status status = Init();
    if (!status.ok()) {
      return status;
    }
  }
  std::ofstream dest(dest_path, std::ios::out);
  bool file_found = false;
  if (!dest.is_open()) {
    return absl::InternalError("Could not open destination file for writing.");
  }

  struct archive_entry* entry;
  while (archive_read_next_header(archive_, &entry) == ARCHIVE_OK) {
    size_t bytes_read;
    char buffer[1024];
    const char* path_name = archive_entry_pathname(entry);
    if (path_name != nullptr && file_name == path_name) {
      while ((bytes_read =
                  archive_read_data(archive_, buffer, sizeof(buffer))) > 0) {
        dest.write(buffer, bytes_read);
      }
      file_found = true;
      break;
    }
  }
  // Set archive to start from beginning for each file
  archive_seek_data(archive_, 0, SEEK_SET);

  dest.close();
  if (file_found == true) {
    return absl::OkStatus();
  }
  return absl::NotFoundError(
      absl::StrFormat("%s not found in archive", file_name));
}

absl::Status ArchiveHandler::WriteAllToDisk(std::string dest_path) {
  if (archive_ == nullptr){
    absl::Status status = Init();
    if (!status.ok()) {
      return status;
    }
  }
  int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM |
        ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS;

  absl::Status status = absl::OkStatus();
  struct archive_entry* entry;
  while (archive_read_next_header(archive_, &entry) == ARCHIVE_OK) {
    std::string outputPathEntry = absl::StrCat(dest_path, "/" ,
                                    archive_entry_pathname(entry));
    archive_entry_set_pathname(entry, outputPathEntry.c_str());
    if (archive_read_extract(archive_, entry, flags) != ARCHIVE_OK) {
        status = absl::InternalError(absl::StrFormat("libarchive: %s",
                                        archive_error_string(archive_)));
        break;
    }
  }

  // Set archive to start from beginning for each file
  archive_seek_data(archive_, 0, SEEK_SET);
  return absl::OkStatus();
}

void ArchiveHandler::Finish() {
  if (archive_ != nullptr) {
    archive_read_close(archive_);
    archive_read_free(archive_);
    archive_ = nullptr;
  }
}

ArchiveHandler::~ArchiveHandler() { Finish(); }

}  // namespace ebpf_monitor
