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

#include "ebpf_monitor/utils/source_helper.h"

#include <cstdlib>
#include <fstream>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "ebpf_monitor/utils/archive_handler.h"
#include "ebpf_monitor/utils/elf_reader.h"
#include "ebpf_monitor/utils/os_helper.h"
#include "bpf/libbpf.h"
#include "re2/re2.h"
#include "ebpf_monitor/utils/dwarf_reader.h"
#include "ebpf_monitor/utils/utils.h"
#include "ebpf_monitor/utils/proc_reader.h"

extern unsigned char _binary_reduced_btfs_tar_gz_start[] __attribute__((weak));
extern unsigned char _binary_reduced_btfs_tar_gz_end[] __attribute__((weak));
extern unsigned char _binary_sources_tar_gz_start[] __attribute__((weak));
extern unsigned char _binary_sources_tar_gz_end[] __attribute__((weak));

namespace ebpf_monitor {

bool TestProgType(bpf_prog_type type) {
  return libbpf_probe_bpf_prog_type(type, NULL) == 1;
}

static absl::StatusOr<uint32_t> get_kernel_version_file() {
  std::ifstream file("/usr/include/linux/version.h");
  if (!file) {
    return absl::InternalError("Could not open version header file");
  }

  std::string contents((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());

  int retVal;
  std::string version;
  if (RE2::PartialMatch(contents, "#define\\s+LINUX_VERSION_CODE\\s+(\\d+)",
                        &version)) {
    if (!absl::SimpleAtoi(version, &retVal)) {
      file.close();
      return absl::InternalError("Could not conver version to integer");
    } else {
      file.close();
      return retVal;
    }
  }

  file.close();
  return absl::NotFoundError("Could not find version from file");
}

/*
  In older kernels while loading kprobes the kernel versions are checked.
  Some kernels don't report versions in a straight forward way via uname.

  Following https://github.com/iovisor/bpftrace/issues/274

  The best way is to read kernel version is reading it in the notes of vdso.
  If that fails we can grep it from the file "/usr/include/linux/version.h"
*/
absl::StatusOr<uint32_t> GetKernelVersion() {
  auto version = ebpf_monitor::ElfReader::GetKernelVersion();
  if (version.ok()) {
    return *version;
  }
  std::cerr << "WARN: " << version.status() << std::endl;

  version = get_kernel_version_file();
  if (version.ok()) {
    return *version;
  }
  return absl::InternalError("Could not find version");
}

bool VmlinuxExists() {
  if (!access("/sys/kernel/btf/vmlinux", R_OK)) return true;
  return false;
}

absl::StatusOr<SourceLanguage> DetectSourceLanguauge(int pid){
  auto path = GetBinaryPath(pid);
  if (!path.ok()) {
    return path.status();
  }
  DwarfReader reader(*path);
  return reader.GetSourceLanguage();
}


absl::StatusOr<std::string> GetBtfFilePath() {
  OsHelper helper;
  std::string write_path = "/tmp/lightfoot.reduced.bpf";
  auto status = helper.CaptureOsInfo();
  if (!status.ok()) {
    return status;
  }
  auto path = helper.GetBtfArchivePath();
  if (!path.ok()) return path.status();

  if (!_binary_reduced_btfs_tar_gz_start) {
    return absl::InternalError("Reduced binary not linked");
  }
  ArchiveHandler handler(
      _binary_reduced_btfs_tar_gz_start,
      _binary_reduced_btfs_tar_gz_end - _binary_reduced_btfs_tar_gz_start);
  status = handler.Init();
  if (!status.ok()) return status;
  status = handler.WriteFileToDisk(*path, write_path);
  if (!status.ok()) return status;

  if (access(write_path.c_str(), R_OK)) {
    return absl::InternalError("Writing reduced btf file failed");
  }
  return write_path;
}


absl::Status SourceExtractionHelper::ExtractSources(){
  // Create a temporary directory
  if (mkdtemp(temp_dir_template_) == nullptr) {
      return absl::InternalError("Failed to create temporary directory");
  }
  if (!_binary_sources_tar_gz_start) {
    return absl::InternalError("Reduced sources not linked");
  }
  ArchiveHandler handler(
      _binary_sources_tar_gz_start,
      _binary_sources_tar_gz_end - _binary_sources_tar_gz_start);
  auto status = handler.Init();
  if (!status.ok()) return status;
  status = handler.WriteAllToDisk(temp_dir_template_);
  handler.Finish();
  if (!status.ok()) return status;
  extracted_ = true;
  return absl::OkStatus();
}

absl::StatusOr<absl::string_view>
    SourceExtractionHelper::GetSourceExtrationPath (){
  if (!extracted_){
    auto status = ExtractSources();
    if (!status.ok()) return status;
  }
  return temp_dir_template_;
}
SourceExtractionHelper::~SourceExtractionHelper() {
  if (extracted_){
  system(absl::StrFormat("exec rm -r %s", temp_dir_template_).c_str());
  }
}
}  // namespace ebpf_monitor
