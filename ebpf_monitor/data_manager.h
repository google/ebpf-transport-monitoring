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

#ifndef _DATA_MANAGER_H_
#define _DATA_MANAGER_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "ebpf_monitor/exporter/handlers.h"
#include "ebpf_monitor/source/data_ctx.h"
#include "event2/event.h"

namespace ebpf_monitor {
class DataManager {
 public:
  DataManager();
  ~DataManager();
  absl::Status Init();
  absl::Status Register(std::shared_ptr<DataCtx> ctx);
  void AddExternalLogHandler(LogHandlerInterface *log_handler);
  void AddExternalMetricHandler(MetricHandlerInterface *metric_handler);
  absl::Status AddLogHandler(absl::string_view name,
                             std::shared_ptr<LogHandlerInterface> log_handler);
  absl::Status AddMetricHandler(
      absl::string_view name,
      std::shared_ptr<MetricHandlerInterface> metric_handler);

 private:
  struct DataManagerCtx {
    void *this_;
    DataCtx *ctx;
  };
  void ReadMap(const struct DataManagerCtx *d_ctx);
  absl::Status RegisterLog(std::shared_ptr<DataCtx> ctx);
  absl::Status RegisterMetric(std::shared_ptr<DataCtx> ctx);
  static void HandleLostEvents(void *ctx, int cpu, __u64 lost_cnt);
  static void HandlePerf(void *arg, int cpu, void *data, uint32_t data_sz);
  static void HandleEvent(evutil_socket_t, short, void *arg);    // NOLINT
  static void HandleCleanup(evutil_socket_t, short, void *arg);  // NOLINT
  absl::flat_hash_map<std::string, std::shared_ptr<DataCtx>> data_sources_;
  absl::flat_hash_map<std::string, bool> registered_sources_;
  absl::flat_hash_map<std::string,
                      std::vector<std::shared_ptr<LogHandlerInterface>>>
      log_handlers_;
  absl::flat_hash_map<std::string,
                      std::vector<std::shared_ptr<MetricHandlerInterface>>>
      metric_handlers_;
  std::vector<MetricHandlerInterface *> ext_metric_handlers_;
  std::vector<LogHandlerInterface *> ext_log_handlers_;
  std::vector<struct event *> events_;
  void *memory_;
};

}  // namespace ebpf_monitor

#endif  // _DATA_MANAGER_H_
