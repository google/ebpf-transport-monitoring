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

#ifndef _EBPF_MONITOR_SOURCE_DATA_CTX_H_
#define _EBPF_MONITOR_SOURCE_DATA_CTX_H_

#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "ebpf_monitor/exporter/data_types.h"
#include "bpf/libbpf.h"

namespace ebpf_monitor {

class DataCtx {
 public:
  enum SourceType {
    kUninitialized,
    kLog,
    kMetric,
  };
  DataCtx(absl::string_view name, LogDesc log_desc, absl::Duration poll,
          bool internal, bool shared)
      : type_(kLog),
        name_(name),
        log_desc_(log_desc),
        poll_(poll),
        internal_(internal),
        shared_(shared) {}
  DataCtx(absl::string_view name, MetricDesc metric_desc, absl::Duration poll,
          bool internal, bool shared)
      : type_(kMetric),
        name_(name),
        metric_desc_(metric_desc),
        poll_(poll),
        internal_(internal),
        shared_(shared) {}
  bpf_map *get_map() { return map_; }
  void set_map(bpf_map *map) { map_ = map; }
  void IncrementLostEvents(uint32_t lost_events) {
    lost_events_ += lost_events;
  }
  uint32_t GetLostEvents() { return lost_events_; }
  int get_bpf_map_fd() { return bpf_map_fd_; }
  void set_bpf_map_fd(int fd) { bpf_map_fd_ = fd; }
  struct perf_buffer *get_buffer() { return buffer_; }
  void set_buffer(struct perf_buffer *buffer) { buffer_ = buffer; }
  absl::string_view get_name() { return name_; }
  absl::Duration get_poll() { return poll_; }
  SourceType get_type() { return type_; }
  bool is_internal() { return internal_; }
  bool is_shared() { return shared_; }
  LogDesc &get_log_desc() { return log_desc_; }
  MetricDesc &get_metric_desc() { return metric_desc_; }
  ~DataCtx() {}

 private:
  SourceType type_;
  std::string name_;
  union {
    MetricDesc metric_desc_;
    LogDesc log_desc_;
  };
  absl::Duration poll_;
  bpf_map *map_;
  int bpf_map_fd_;
  struct perf_buffer *buffer_;
  bool internal_;
  bool init_;
  uint32_t lost_events_;
  bool shared_;
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_SOURCE_DATA_CTX_H_
