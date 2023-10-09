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

#ifndef _EBPF_MONITOR_SOURCE_PROBES_H_
#define _EBPF_MONITOR_SOURCE_PROBES_H_

#include <sys/stat.h>
#include <sys/types.h>

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "bpf/libbpf.h"

namespace ebpf_monitor {

class Probe {
 public:
  explicit Probe(absl::string_view name)
      : name_(name), prog_(nullptr), link_(nullptr) {}

  void set_prog(bpf_program *prog) { prog_ = prog; }
  const bpf_program * get_prog() const { return prog_; }
  void set_prog_fd(int fd) { prog_fd_ = fd; }
  void set_link(bpf_link *link) { link_ = link; }
  const std::string &get_name() const { return name_; }
  virtual absl::Status Attach() = 0;
  virtual absl::Status Detach() {
    if (link_ == nullptr) return absl::OkStatus();
    auto err = bpf_link__destroy(link_);
    if (err) {
      char errBuffer[128] = {0};
      libbpf_strerror(err, errBuffer, sizeof(errBuffer));
      return absl::InternalError(
          absl::StrFormat("Detach Failed %s", errBuffer));
    }
    link_ = nullptr;
    return absl::OkStatus();
  }

  virtual ~Probe() {
    if (link_ == nullptr) return;
    bpf_link__destroy(link_);
  }

 private:
  std::string name_;
  struct bpf_program *prog_;
  struct bpf_link *link_;
  int prog_fd_;
};

class RawTPProbe : public Probe {
 public:
  RawTPProbe(absl::string_view name, absl::string_view probe_cat,
             absl::string_view  probe_fn)
      : Probe(name), probe_cat_(probe_cat), probe_fn_(probe_fn) {}
  absl::Status Attach() override {
    auto prog = get_prog();
    if (prog == nullptr) return absl::NotFoundError("Prog not set");
    auto link = bpf_program__attach_raw_tracepoint(prog, probe_fn_.c_str());
    if (libbpf_get_error(link)) {
      return absl::InternalError(absl::StrCat("Attach failed, errno=",
                                              libbpf_get_error(link)));
    }
    set_link(link);
    set_prog_fd(bpf_link__fd(link));
    return absl::OkStatus();
  }
 private:
  std::string probe_cat_;
  std::string probe_fn_;
};

class UProbe : public Probe {
 public:
  UProbe(absl::string_view name, absl::string_view binary_name,
         uint64_t func_offset, bool retprobe)
      : Probe(name),
        binary_name_(binary_name),
        func_offset_(func_offset),
        retprobe_(retprobe){}
  absl::Status Attach() override {
    auto prog = get_prog();
    if (prog == nullptr) return absl::NotFoundError("Prog not set");
    auto link = bpf_program__attach_uprobe(prog, retprobe_, -1,
                                       binary_name_.c_str(), func_offset_);
    if (link == nullptr) {
      return absl::InternalError(absl::StrCat("Attach failed, errno=",
                                            libbpf_get_error(link)));
    }
    set_link(link);
    set_prog_fd(bpf_link__fd(link));
    return absl::OkStatus();
  }

 private:
  std::string binary_name_;
  uint64_t func_offset_;
  bool retprobe_;
};

class KProbe : public Probe {
 public:
  KProbe(absl::string_view name, absl::string_view function_name, bool retprobe)
      : Probe(name), function_name_(function_name), retprobe_(retprobe) {}
  absl::Status Attach() override {
    auto prog = get_prog();
    if (prog == nullptr) return absl::NotFoundError("Prog not set");
    auto link =
        bpf_program__attach_kprobe(prog, retprobe_, function_name_.c_str());
    if (link == nullptr) {
      return absl::InternalError(absl::StrCat("Attach failed, errno=",
                                            libbpf_get_error(link)));
    }
    set_link(link);
    set_prog_fd(bpf_link__fd(link));
    return absl::OkStatus();
  }

 private:
  std::string function_name_;
  bool retprobe_;
};
}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_SOURCE_PROBES_H_
