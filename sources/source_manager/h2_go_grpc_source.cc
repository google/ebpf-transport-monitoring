// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
//
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

#include "sources/source_manager/h2_go_grpc_source.h"

#include <memory>
#include <iostream>
#include <string>
#include <cstdint>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "ebpf_monitor/source/probes.h"
#include "ebpf_monitor/utils/elf_reader.h"
#include "ebpf_monitor/utils/dwarf_reader.h"
#include "ebpf_monitor/utils/proc_reader.h"
#include "ebpf_monitor/utils/sym_addrs.h"
#include "sources/common/h2_symaddrs.h"
#include "sources/common/sym_types.h"
#include "bpf/libbpf.h"

#include "re2/re2.h"

#define EBPF_TM_RETURN_IF_ERROR(status) \
  if (!status.ok()) {        \
    return status;           \
  }
namespace {

absl::Status GetValue(ebpf_monitor::DwarfReader& reader,
                      std::string struct_name, std::string member_name,
                      member_var_t* member, int32_t size) {
  auto mem = reader.GetMemberVar(struct_name, member_name);
  if (!mem.ok()) {
    return mem.status();
  }
  *member = *mem;
  if (member->size == -1) {
    member->size = size;
  }
  return absl::OkStatus();
}

absl::Status GetStructOffsets(std::string& path, h2_cfg_t* bpf_cfg) {
  absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> > structs;

  structs["http2.FrameHeader"] = {
      {"Type"}, {"Flags"}, {"Length"}, {"StreamID"}};
  structs["http2.DataFrame"] = {{"data"}};
  structs["http2.RSTStreamFrame"] = {{"ErrCode"}};
  structs["http2.SettingsFrame"] = {{"p"}};
  structs["http2.GoAwayFrame"] = {{"ErrCode"}, {"LastStreamID"}, {"debugData"}};
  structs["transport.http2Client"] = {
      {"framer"}, {"localAddr"}, {"remoteAddr"}};
  structs["transport.http2Server"] = {
      {"framer"}, {"localAddr"}, {"remoteAddr"}};
  structs["transport.framer"] = {
      {"writer"},
  };
  structs["net.TCPAddr"] = {{"IP"}, {"Port"}};

  ebpf_monitor::DwarfReader reader(path);
  absl::Status status = reader.FindStructs(structs);
  if (!status.ok()) {
    // use default values
    bpf_cfg->offset = {
        .frameheader_type = {.offset = 1, .size = 1},
        .frameheader_flags = {.offset = 2, .size = 1},
        .frameheader_length = {.offset = 4, .size = 4},
        .frameheader_streamid = {.offset = 8, .size = 4},
        .dataframe_data = {.offset = 16, .size = sizeof(struct go_slice)},
        .rstframe_error = {.offset = 12, .size = 4},
        .goawayframe_error = {.offset = 16, .size = 4},
        .goawayframe_stream = {.offset = 12, .size = 4},
        .goawayframe_data = {.offset = 20, .size = sizeof(struct go_slice)},
        .settingsframe_data = {.offset = 16, .size = sizeof(struct go_slice)},
        .client_framer = {.offset = 160, .size = sizeof(uint64_t)},
        .server_framer = {.offset = 128, .size = sizeof(uint64_t)},
        .framer_bufwriter = {.offset = 0, .size = sizeof(uint64_t)},
        .client_laddr = {.offset = 104, .size = sizeof(struct go_interface)},
        .client_raddr = {.offset = 88, .size = sizeof(struct go_interface)},
        .server_laddr = {.offset = 88, .size = sizeof(struct go_interface)},
        .server_raddr = {.offset = 72, .size = sizeof(struct go_interface)},
        .tcp_ip = {.offset = 0, .size = 16},
        .tcp_port = {.offset = 24, .size = 8}};
  } else {
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.FrameHeader", "Type",
                          &bpf_cfg->offset.frameheader_type, 1));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.FrameHeader", "Flags",
                          &bpf_cfg->offset.frameheader_flags, 1));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.FrameHeader", "Length",
                          &bpf_cfg->offset.frameheader_length, 4));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.FrameHeader", "StreamID",
                          &bpf_cfg->offset.frameheader_streamid, 4));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.DataFrame", "data",
                          &bpf_cfg->offset.dataframe_data,
                          sizeof(struct go_slice)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.RSTStreamFrame", "ErrCode",
                          &bpf_cfg->offset.rstframe_error, -1));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "transport.http2Client", "framer",
                          &bpf_cfg->offset.client_framer, sizeof(uint64_t)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "transport.http2Client",
                                     "localAddr",
                                     &bpf_cfg->offset.client_laddr,
                                     sizeof(struct go_interface)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "transport.http2Client",
                                     "remoteAddr",
                                      &bpf_cfg->offset.client_raddr,
                                      sizeof(struct go_interface)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "transport.http2Server",
                                     "localAddr",
                                    &bpf_cfg->offset.server_laddr,
                                    sizeof(struct go_interface)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "transport.http2Server",
                                     "remoteAddr",
                                    &bpf_cfg->offset.server_raddr,
                                    sizeof(struct go_interface)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "transport.http2Server", "framer",
                          &bpf_cfg->offset.server_framer, sizeof(uint64_t)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "transport.framer", "writer",
                          &bpf_cfg->offset.framer_bufwriter, sizeof(uint64_t)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.SettingsFrame", "p",
                          &bpf_cfg->offset.settingsframe_data, -1));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.GoAwayFrame", "ErrCode",
                          &bpf_cfg->offset.goawayframe_error, -1));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.GoAwayFrame",
                                     "LastStreamID",
                                     &bpf_cfg->offset.goawayframe_stream, -1));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "http2.GoAwayFrame", "debugData",
                          &bpf_cfg->offset.goawayframe_data,
                          sizeof(struct go_slice)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "net.TCPAddr", "IP",
                                     &bpf_cfg->offset.tcp_ip,
                          sizeof(struct go_slice)));
    EBPF_TM_RETURN_IF_ERROR(GetValue(reader, "net.TCPAddr", "Port",
                          &bpf_cfg->offset.tcp_port, sizeof(uint64_t)));
  }
  return absl::OkStatus();
}

absl::Status GetTypes(ebpf_monitor::ElfReader* elf_reader, h2_cfg_t* bpf_cfg) {
  absl::flat_hash_set<std::string> symbols;
  symbols.insert("go:itab.*net.TCPAddr,net.Addr");
  symbols.insert("go.itab.*net.TCPAddr,net.Addr");
  auto status =
      elf_reader->FindSymbols(symbols, ebpf_monitor::ElfReader::kValue);
  EBPF_TM_RETURN_IF_ERROR(status);

#define GET_VALUE(sym1, sym2, value)                              \
  if (elf_reader->GetSymbol(sym1).ok()) {                         \
    value = *(elf_reader->GetSymbol(sym1));                       \
  } else if (elf_reader->GetSymbol(sym2).ok()) {                  \
    value = *(elf_reader->GetSymbol(sym2));                       \
  } else {                                                        \
    return absl::NotFoundError(                                   \
        absl::StrFormat("Type %s and %s not found", sym1, sym2)); \
  }
  GET_VALUE("go:itab.*net.TCPAddr,net.Addr", "go.itab.*net.TCPAddr,net.Addr",
            bpf_cfg->types.tcp_addr);
#undef GET_VALUE
  return absl::OkStatus();
}

absl::Status GetGolangVersion(ebpf_monitor::ElfReader* elf_reader,
                              int* major_version, int* minor_version) {
  absl::flat_hash_set<std::string> functions;
  functions.insert("runtime.buildVersion");
  absl::Status status =
      elf_reader->FindSymbols(functions, ebpf_monitor::ElfReader::kOffset);
  EBPF_TM_RETURN_IF_ERROR(status);

  auto offset = elf_reader->GetSymbol("runtime.buildVersion");
  if (offset.ok() == false) {
    return absl::InternalError("Could not find go version");
  }
  std::vector<char> buffer(16, 0);
  status =
      elf_reader->ReadData(nullptr, *offset, buffer.data(),
                           sizeof(struct go_string));
  EBPF_TM_RETURN_IF_ERROR(status);
  struct go_string* str = (struct go_string*)buffer.data();
  status = elf_reader->ReadData(".rodata", (uint64_t)str->ptr,
                                buffer.data(), 15);
  EBPF_TM_RETURN_IF_ERROR(status);
  if (!RE2::PartialMatch(std::string(buffer.data(), 15), "go(\\d+).(\\d+)",
                         major_version, minor_version)) {
    return absl::InternalError(
        absl::StrCat("Could not regex match go version", buffer.data()));
  }
  return status;
}
}  //  namespace

namespace ebpf_monitor {

// File name is hardcoded with a relative location for now.
// Will do something better later.
H2GoGrpcSource::H2GoGrpcSource()
    : Source::Source(
          {},
          {std::make_shared<DataCtx>("h2_events", LogDesc{},
                                     absl::Seconds(2), false, true),
           std::make_shared<DataCtx>("h2_grpc_correlation", LogDesc{},
                                     absl::Seconds(2), true, false)},
          {
              std::make_shared<DataCtx>("h2_stream_count",
                                        MetricDesc{MetricType::kUint64,
                                                   MetricType::kUint64,
                                                   MetricKind::kCumulative,
                                                   {MetricUnitType::kNone}},
                                        absl::Seconds(60), false, true),
              std::make_shared<DataCtx>("h2_reset_stream_count",
                                        MetricDesc{MetricType::kUint64,
                                                   MetricType::kUint64,
                                                   MetricKind::kCumulative,
                                                   {MetricUnitType::kNone}},
                                        absl::Seconds(60), false, true),
              std::make_shared<DataCtx>("h2_ping_counter",
                                        MetricDesc{MetricType::kUint64,
                                                   MetricType::kUint64,
                                                   MetricKind::kCumulative,
                                                   {MetricUnitType::kNone}},
                                        absl::Seconds(60), true, true),
              std::make_shared<DataCtx>("h2_stream_id",
                                        MetricDesc{MetricType::kUint64,
                                                   MetricType::kUint64,
                                                   MetricKind::kNone,
                                                   {MetricUnitType::kNone}},
                                        absl::Seconds(60), true, true),
              std::make_shared<DataCtx>("h2_grpc_pid_filter",
                                        MetricDesc{MetricType::kUint64,
                                                   MetricType::kUint64,
                                                   MetricKind::kNone,
                                                   {MetricUnitType::kNone}},
                                        absl::Seconds(60), true, false),
              std::make_shared<DataCtx>("h2_connection",
                                        MetricDesc{MetricType::kUint64,
                                                   MetricType::kInternal,
                                                   MetricKind::kNone,
                                                   {MetricUnitType::kNone}},
                                        absl::Seconds(60), true, true),
          },
          "./h2_bpf.o", "./h2_bpf_core.o", "h2_grpc_pid_filter") {}

static void InitCfg(h2_cfg_t* bpf_cfg) {
  bpf_cfg->variables = {
      .connection = {.type = kLocationTypeRegisters, .offset = 0},
      .frame = {.type = kLocationTypeRegisters, .offset = 1},
      .buf_writer = {.type = kLocationTypeRegisters, .offset = 0},
      .write_buffer_len = {.type = kLocationTypeRegisters, .offset = 2},
      .write_buffer_ptr = {.type = kLocationTypeRegisters, .offset = 1},
  };
}

absl::Status H2GoGrpcSource::CreateProbes(
    ElfReader* elf_reader, std::string& path,
    absl::flat_hash_set<std::string>& functions, const char* probe_func) {
  auto status = elf_reader->FindSymbols(functions, ElfReader::kOffset);
  if (!status.ok()) {
    return status;
  }

  int count = 0;
  for (auto it = functions.begin(); it != functions.end(); ++it) {
    auto offset = elf_reader->GetSymbol(*it);
    if (!offset.ok()) {
      std::cerr << offset.status() << "\n";
      continue;
    }
    count++;
    probes_.push_back(
        std::make_shared<UProbe>(probe_func, path, *offset, false));
  }

  if (count == 0) {
    return absl::InternalError("Could not find any address.");
  }

  return absl::OkStatus();
}

absl::Status H2GoGrpcSource::RegisterProbes(ElfReader* elf_reader,
                                            std::string& path, uint64_t pid) {
  /* The unimportant functions are commented.*/
  absl::flat_hash_set<std::string> client_functions{
      {"transport.(*http2Client).handleData"},
      {"transport.(*http2Client).handleRSTStream"},
      {"transport.(*http2Client).handleGoAway"},
  };
  auto status = CreateProbes(elf_reader, path, client_functions,
                             "probe_handle_client_data");
  EBPF_TM_RETURN_IF_ERROR(status);

  absl::flat_hash_set<std::string> server_functions{
      {"transport.(*http2Server).handleData"},
      {"transport.(*http2Server).handleRSTStream"},
  };
  status = CreateProbes(elf_reader, path, server_functions,
                        "probe_handle_server_data");
  EBPF_TM_RETURN_IF_ERROR(status);
  absl::flat_hash_set<std::string> server_header_functions{
      {"transport.(*http2Server).operateHeaders"}};
  status = CreateProbes(elf_reader, path, server_header_functions,
                        "probe_handle_server_header");
  EBPF_TM_RETURN_IF_ERROR(status);
  absl::flat_hash_set<std::string> client_header_functions{
      {"transport.(*http2Client).operateHeaders"}};
  status = CreateProbes(elf_reader, path, client_header_functions,
                        "probe_handle_client_header");
  EBPF_TM_RETURN_IF_ERROR(status);
  absl::flat_hash_set<std::string> buf_writer_functions{
      {"transport.(*bufWriter).Write"}};
  status = CreateProbes(elf_reader, path, buf_writer_functions,
                        "probe_sent_frame");
  EBPF_TM_RETURN_IF_ERROR(status);
  absl::flat_hash_set<std::string> close_functions{
      {"transport.(*http2Client).Close"}, {"transport.(*http2Server).Close"}};
  return CreateProbes(elf_reader, path, close_functions, "probe_close");
}

absl::Status H2GoGrpcSource::AddPID(pid_t pid) {
  absl::Status status;
  int major_version, minor_version;
  if (bpf_cfg_.find(pid) != bpf_cfg_.end()) {
    return absl::AlreadyExistsError(absl::StrFormat("Pid %d", pid));
  }
  auto path = GetBinaryPath(pid);
  if (!path.ok()) {
    return path.status();
  }
  // If probes are already attached no need to do the following steps again.
  // Just copy the config to the corresponding to that pid
  if (pid_path_map_.find(*path) != pid_path_map_.end()) {
    status = Source::AddPID(pid);
    EBPF_TM_RETURN_IF_ERROR(status);
    bpf_cfg_[pid] = bpf_cfg_[pid_path_map_[*path][0]];
    pid_path_map_[*path].push_back(pid);
    return absl::OkStatus();
  }
  std::cout << "Path:" << *path << std::endl;
  ElfReader elf_reader(*path);
  status =
      GetGolangVersion(&elf_reader, &major_version, &minor_version);
  EBPF_TM_RETURN_IF_ERROR(status);

  if (major_version >= 1 && minor_version > 16) {
    // use register based config
  } else {
    absl::PrintF("Golang Version %d %d", major_version, minor_version);
    return absl::UnimplementedError("Stack based reg not tested yet.");
  }

  h2_cfg_t bpf_cfg;

  InitCfg(&bpf_cfg);
  status = GetStructOffsets(*path, &bpf_cfg);
  EBPF_TM_RETURN_IF_ERROR(status);

  status = GetTypes(&elf_reader, &bpf_cfg);
  EBPF_TM_RETURN_IF_ERROR(status);

  status = RegisterProbes(&elf_reader, *path, pid);
  EBPF_TM_RETURN_IF_ERROR(status);

  bpf_cfg_[pid] = bpf_cfg;
  pid_path_map_[*path].push_back(pid);
  status = Source::AddPID(pid);
  EBPF_TM_RETURN_IF_ERROR(status);
  EBPF_TM_RETURN_IF_ERROR(AddCfg(pid));
  EBPF_TM_RETURN_IF_ERROR(Source::LoadProbes());
  return absl::OkStatus();
}

absl::Status H2GoGrpcSource::RemovePID(pid_t pid) {
  absl::Status status = Source::RemovePID(pid);
  EBPF_TM_RETURN_IF_ERROR(status);
  bpf_cfg_.erase(pid);
  std::string binary_path;

  for (auto&[path, pid_map] : pid_path_map_) {
    for (int i=0; i < pid_map.size(); ++i) {
      if (pid_map[i] == pid) {
        binary_path = path;
        pid_map.erase(pid_map.begin() + i);
        break;
      }
    }
  }

  if (!binary_path.empty()) {
    if (pid_path_map_.find(binary_path) != pid_path_map_.end()) {
      if (pid_path_map_[binary_path].empty()) {
        for (int i = probes_.size() - 1; i >= 0; i--) {
          UProbe* uprobe = static_cast<UProbe*> (probes_[i].get());
          if (uprobe->binary_name() == binary_path) {
            status = uprobe->Detach();
            if (!status.ok()) {
              std::cerr << status << "\n";
            }
            probes_.erase(probes_.begin() + i);
          }
        }
      }
      pid_path_map_.erase(binary_path);
    }
  }
  // Destroy Probes.
  return absl::OkStatus();
}

absl::Status H2GoGrpcSource::AddCfg(uint64_t pid) {
  auto map = bpf_object__find_map_by_name(obj_, "h2_cfg");
  if (map == nullptr) {
    return absl::NotFoundError("Could not find config map");
  }

  if (bpf_cfg_.find(pid) == bpf_cfg_.end()) {
    return absl::NotFoundError(absl::StrFormat("Config not found for pid %d",
                                               pid));
  }

  int upd_status =
      bpf_map__update_elem(map, &pid, sizeof(uint64_t),
                            &bpf_cfg_[pid], sizeof(h2_cfg_t), 0/*BPF_ANY*/);
  if (upd_status != 0) {
    return absl::InternalError(
        absl::StrFormat("Could not set initial value for map %d: %d",
                        bpf_map__type(map), upd_status));
  }
  return absl::OkStatus();
}

H2GoGrpcSource::~H2GoGrpcSource() { Cleanup(); }

}  // namespace ebpf_monitor
