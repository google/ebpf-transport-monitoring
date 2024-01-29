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

#include "ebpf_monitor/source/source.h"

#include <memory>
#include <iostream>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "ebpf_monitor/source/probes.h"
#include "ebpf_monitor/utils/map_memory.h"
#include "ebpf_monitor/utils/source_helper.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

namespace ebpf_monitor {


Source::Source(std::vector<std::shared_ptr<Probe>> probes,
               std::vector<std::shared_ptr<DataCtx>> log_sources,
               std::vector<std::shared_ptr<DataCtx>> metric_sources,
               absl::string_view file_name, absl::string_view file_name_core,
               absl::string_view pid_filter_map)
    : file_name_(std::move(file_name)),
      file_name_core_(std::move(file_name_core)),
      probes_(probes),
      log_sources_(log_sources),
      metric_sources_(metric_sources),
      pid_filter_map_(pid_filter_map),
      init_(false) {}

absl::Status Source::Init(bool extract_source) {
  struct bpf_object_open_opts open_opts;
  memset(&open_opts, 0, sizeof(struct bpf_object_open_opts));
  open_opts.sz = sizeof(struct bpf_object_open_opts);

  bool core = true;
  if (!VmlinuxExists()) {
    auto path = GetBtfFilePath();
    if (path.ok()) {
      open_opts.btf_custom_path = strdup(path->c_str());
    } else {
      core = false;
    }
  }
  std::string dir_path;
  if (extract_source) {
    auto path =
        SourceExtractionHelper::GetInstance().GetSourceExtrationPath();
    if (!path.ok()){
      std::cerr << path.status() << std::endl;
      dir_path = ".";
    }else {
      dir_path = std::string(*path);
    }
  } else {
    dir_path = ".";
  }
  if (!core) {
    // This means that this is non-core code.
    std::cout <<
        "Loading " << file_name_ << std::endl;
    obj_ = bpf_object__open_file(file_name_.c_str(), &open_opts);
  } else {
    auto file_name_core = absl::StrFormat("%s/%s", dir_path, file_name_core_);
    std::cout << "Loading " << file_name_core << std::endl;
    obj_ = bpf_object__open_file(file_name_core.c_str(), &open_opts);
    if (libbpf_get_error(obj_)) {
      std::cout << "Loading " << file_name_ << std::endl;
      obj_ = bpf_object__open_file(file_name_.c_str(), &open_opts);
    }
  }
  if (obj_ == nullptr) {
    return absl::NotFoundError("'BPF object not found");
  }
  auto version = GetKernelVersion();
  if (version.ok()) {
    bpf_object__set_kversion(obj_, *version);
  } else {
    // This is not a fatal error in some cases hence warn.
    std::cerr << "Warn: " << version.status() << std::endl;
  }
  return absl::OkStatus();
}

absl::Status Source::LoadObj() {
  char errBuffer[50] = {0};
  absl::Status status;
  status = ShareMaps();
  if (!status.ok()) {
    return status;
  }
  auto err = bpf_object__load(obj_);
  if (err) {
    libbpf_strerror(err, errBuffer, sizeof(errBuffer));
    return absl::InternalError("Object load error:" + std::string(errBuffer));
  }
  return absl::OkStatus();
}

absl::Status Source::LoadProbes() {
  absl::Status status;
  for (auto& probe : probes_) {
    if (probe->is_attached()) continue;
    auto prog =
        bpf_object__find_program_by_name(obj_, probe->get_name().c_str());
    if (libbpf_get_error(prog)) {
      status = absl::NotFoundError(
          absl::StrFormat("Probe %s not found", probe->get_name()));
      goto cleanup;
    }
    probe->set_prog(prog);
    status = probe->Attach();
    if (!status.ok()) {
      goto cleanup;
    }
  }
  return absl::OkStatus();
cleanup:
  Cleanup();
  return status;
}

absl::Status Source::ShareMaps() {
  char errBuffer[50] = {0};
  struct bpf_map* map;
  bpf_object__for_each_map(map, obj_) {
    const char* name = bpf_map__name(map);
    if (name == nullptr) {
      continue;
    }
    auto map_fd = MapMemory::GetInstance().GetMap(name);
    if (map_fd.ok()) {
      int err = bpf_map__reuse_fd(map, *map_fd);
      if (err < 0) {
        libbpf_strerror(err, errBuffer, sizeof(errBuffer));
        return absl::InternalError(
            absl::StrFormat("Could not reuse fd %d for map %s: %s",
                            *map_fd, name, errBuffer));
      }
    }
  }
  return absl::OkStatus();
}

absl::Status Source::LoadMaps() {
  absl::Status status;
  for (auto& ctx : metric_sources_) {
    auto* map = bpf_object__find_map_by_name(obj_, ctx->get_name().begin());
    if (libbpf_get_error(map)) {
      status = absl::NotFoundError(
          absl::StrFormat("Map %s not found", ctx->get_name()));
      goto cleanup;
    }
    ctx->set_map(map);
    ctx->set_bpf_map_fd(bpf_map__fd(map));
  }
  for (auto& ctx : log_sources_) {
    auto* map = bpf_object__find_map_by_name(obj_, ctx->get_name().begin());
    if (libbpf_get_error(map)) {
      status = absl::NotFoundError(
          absl::StrFormat("Map %s not found", ctx->get_name()));
      goto cleanup;
    }
    ctx->set_map(map);
    ctx->set_bpf_map_fd(bpf_map__fd(map));
  }
  init_ = true;
  return absl::OkStatus();
cleanup:
  Cleanup();
  return status;
}

std::vector<std::shared_ptr<DataCtx> >& Source::GetLogSources() {
  return log_sources_;
}

std::vector<std::shared_ptr<DataCtx> >& Source::GetMetricSources() {
  return metric_sources_;
}

void Source::Cleanup() {
  if (init_ == false) {
    return;
  }
  for (auto& probe : probes_) {
    auto status = probe->Detach();
    if (!status.ok()) {
      std::cerr << status << std::endl;
    }
  }
  if (obj_) bpf_object__close(obj_);
}

absl::Status Source::AddPID(pid_t pid) {
  if (init_ == false) {
    return absl::InternalError("Uninitialized");
  }
  auto map_ctx = GetMap(pid_filter_map_);
  if (!map_ctx.ok()) {
    return map_ctx.status();
  }
  uint8_t value = 1;
  int err = bpf_map_update_elem((*map_ctx)->get_bpf_map_fd(), (void*)&pid,
                                (void*)&value, BPF_ANY);
  if (err != 0) {
    return absl::InternalError("Error added PID to filter map");
  }
  return absl::OkStatus();
}

absl::Status Source::RemovePID(pid_t pid) {
  if (init_ == false) {
    return absl::InternalError("Uninitialized");
  }
  auto map_ctx = GetMap(pid_filter_map_);
  if (!map_ctx.ok()) {
    return map_ctx.status();
  }
  int err = bpf_map_delete_elem((*map_ctx)->get_bpf_map_fd(), (void*)&pid);
  if (err != 0) {
    return absl::InternalError("Error removing PID from filter map");
  }
  return absl::OkStatus();
}

absl::Status Source::AttachProbe(absl::string_view probe_name) {
  std::vector<std::shared_ptr<Probe>>::iterator it;
  for (it = probes_.begin(); it != probes_.end(); it++) {
    if ((*it)->get_name() == probe_name) {
      break;
    }
  }
  if (it == probes_.end()) {
    return absl::NotFoundError(
        absl::StrFormat("Probe %s not found", probe_name));
  }
  return (*it)->Attach();
}

absl::Status Source::DetachProbe(absl::string_view probe_name) {
  std::vector<std::shared_ptr<Probe>>::iterator it;
  for (it = probes_.begin(); it != probes_.end(); it++) {
    if ((*it)->get_name() == probe_name) {
      break;
    }
  }
  if (it == probes_.end()) {
    return absl::NotFoundError(
        absl::StrFormat("Probe %s not found", probe_name));
  }
  return (*it)->Detach();
}

absl::StatusOr<std::shared_ptr<DataCtx> > Source::GetMap(
    absl::string_view map_name) {
  for (auto& source : metric_sources_) {
    if (!source->get_name().compare(map_name)) {
      return source;
    }
  }
  for (auto& source : log_sources_) {
    if (!source->get_name().compare(map_name)) {
      return source;
    }
  }
  return absl::NotFoundError(absl::StrFormat("map %s not found", map_name));
}
}  // namespace ebpf_monitor
