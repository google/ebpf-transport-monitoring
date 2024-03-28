#include <cstring>
#include <string>
#include "gmock/gmock.h"
#include "protobuf-matchers/protocol-buffer-matchers.h"
#include "gtest/gtest.h"

#include "ebpf_monitor/utils/archive_handler.h"
#include "bpf/libbpf.h"
#include "bpf/btf.h"


extern unsigned char _binary_reduced_btfs_tar_gz_start[] __attribute__((weak));
extern unsigned char _binary_reduced_btfs_tar_gz_end[] __attribute__((weak));

namespace ebpf_monitor{

// CheckBTFInfo checks if the reduced btf tar file is valid and has the right
// symbols to be linked to the lightfoot binary. It also makes sure the btf
// information can be parsed by the libbpf library.
TEST(BTFTest, CheckBTFInfo) {
  ArchiveHandler handler(
      _binary_reduced_btfs_tar_gz_start,
      _binary_reduced_btfs_tar_gz_end - _binary_reduced_btfs_tar_gz_start);
  ASSERT_OK(handler.Init());
  std::string dir = ::testing::TempDir();
  std::string file1 = dir + "/reduced.btf";
  ASSERT_OK(handler.WriteFileToDisk(
      "./debian/10/x86_64/4.19.0-19-cloud-amd64.btf",
       file1));

  handler.Finish();
  struct btf *file_btf = nullptr;
  file_btf = btf__parse(file1.c_str(), NULL);
  ASSERT_NE(file_btf, nullptr);
  btf__free(file_btf);
}

}  // namespace ebpf_monitor
