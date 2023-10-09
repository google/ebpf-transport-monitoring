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

#include "sources/source_manager/openssl_source.h"

#include <string>
#include <vector>

#include "ebpf_monitor/source/source.h"
#include "ebpf_monitor/utils/proc_reader.h"
#include "bpf/libbpf.h"

namespace ebpf_monitor {

// File name is hardcoded with a relative location for now.
// Will do something better later.
OpenSslSource::OpenSslSource()
    : Source::Source(
          {},
          {
            std::make_shared<DataCtx>("h2_events", LogDesc{}, absl::Seconds(2),
                                     false, true),
            std::make_shared<DataCtx>("openssl_correlation_events", LogDesc{},
                                     absl::Seconds(2), true, false)
          },
          {
              {std::make_shared<DataCtx>("h2_stream_count",
                                         MetricDesc{MetricType::kUint64,
                                                    MetricType::kUint64,
                                                    MetricKind::kCumulative,
                                                    {MetricUnitType::kNone}},
                                         absl::Seconds(60), false, true)},
              {std::make_shared<DataCtx>("h2_reset_stream_count",
                                         MetricDesc{MetricType::kUint64,
                                                    MetricType::kUint64,
                                                    MetricKind::kCumulative,
                                                    {MetricUnitType::kNone}},
                                         absl::Seconds(60), false, true)},
              {std::make_shared<DataCtx>("h2_ping_counter",
                                         MetricDesc{MetricType::kUint64,
                                                    MetricType::kUint64,
                                                    MetricKind::kCumulative,
                                                    {MetricUnitType::kNone}},
                                         absl::Seconds(60), true, true)},
              {std::make_shared<DataCtx>("h2_stream_id",
                                         MetricDesc{MetricType::kUint64,
                                                    MetricType::kUint64,
                                                    MetricKind::kNone,
                                                    {MetricUnitType::kNone}},
                                         absl::Seconds(60), true, true)},
              {std::make_shared<DataCtx>("openssl_pid_filter",
                                         MetricDesc{MetricType::kUint64,
                                                    MetricType::kUint64,
                                                    MetricKind::kNone,
                                                    {MetricUnitType::kNone}},
                                         absl::Seconds(60), true, false)},
              {std::make_shared<DataCtx>("h2_connection",
                                         MetricDesc{MetricType::kUint64,
                                                    MetricType::kInternal,
                                                    MetricKind::kNone,
                                                    {MetricUnitType::kNone}},
                                         absl::Seconds(60), true, true)},
              {std::make_shared<DataCtx>("h2_event_heap",
                                         MetricDesc{MetricType::kUint32,
                                                    MetricType::kInternal,
                                                    MetricKind::kNone,
                                                    {MetricUnitType::kNone}},
                                         absl::Seconds(60), true, true)},
              // openssl_connections is a map of connections which h2 or not
              {std::make_shared<DataCtx>("openssl_connections",
                                         MetricDesc{MetricType::kUint64,
                                                    MetricType::kInternal,
                                                    MetricKind::kNone,
                                                    {MetricUnitType::kNone}},
                                         absl::Seconds(60), true, true)},
          },
          "./openssl_bpf.o", "./openssl_core.o", "openssl_pid_filter") {}

OpenSslSource::~OpenSslSource() { Source::Cleanup(); }

absl::Status OpenSslSource::RegisterProbes(ElfReader* elf_reader,
                                           std::string& path, uint64_t pid) {
  absl::flat_hash_set<std::string> functions{
      {"SSL_read"},
      {"SSL_write"},
  };

  auto status = elf_reader->FindSymbols(functions, ElfReader::kOffset);
  if (!status.ok()) {
    return status;
  }

  int count = 0;
  auto offset = elf_reader->GetSymbol("SSL_read");
  if (!offset.ok()) {
    std::cerr << offset.status() << "\n";
    count++;
  } else {
    probes_.push_back(
        std::make_shared<UProbe>("probe_entry_SSL_read", path, *offset, false));
    probes_.push_back(
        std::make_shared<UProbe>("probe_ret_SSL_read", path, *offset, true));
  }
  offset = elf_reader->GetSymbol("SSL_write");
  if (!offset.ok()) {
    std::cerr << offset.status() << "\n";
    count++;
  } else {
    probes_.push_back(
        std::make_shared<UProbe>("probe_entry_SSL_write",
                                 path, *offset, false));
    probes_.push_back(
        std::make_shared<UProbe>("probe_ret_SSL_write", path, *offset, true));
  }
  if (count != 0) {
    return absl::InternalError("Did not find some function offsets");
  }
  return absl::OkStatus();
}

absl::Status OpenSslSource::AddPID(uint64_t pid) {
  auto path = GetBinaryPath(pid);
  if (!path.ok()) {
    return path.status();
  }

  std::cout << "Path:" << *path << std::endl;
  ElfReader elf_reader(*path);

  return RegisterProbes(&elf_reader, *path, pid);
}

}  // namespace ebpf_monitor
