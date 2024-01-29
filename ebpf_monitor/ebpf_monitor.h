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
#ifndef _EBPF_MONITOR_H_
#define _EBPF_MONITOR_H_

#include <string>
#include <memory>
#include "absl/status/status.h"
#include "ebpf_monitor/data_manager.h"
#include "sources/source_manager/map_source.h"
#include "ebpf_monitor/source/source.h"
#include "ebpf_monitor/exporter/log_exporter.h"
#include "ebpf_monitor/correlator/correlator.h"
#include "ebpf_monitor/exporter/metric_exporter.h"
#include "absl/container/flat_hash_map.h"

namespace ebpf_monitor {

class EbpfMonitor {
 public:
  static EbpfMonitor& GetInstance() {
    static EbpfMonitor instance;
    return instance;
  }
  absl::Status Init(bool dry_run);
  absl::Status Start();
  absl::Status Monitor(pid_t pid);
  absl::Status StopMonitoring(pid_t pid);

 private:
  EbpfMonitor();
  absl::Status CreateLoggers();
  absl::Status MapSourceInit();
  void CreateSourcesCorrelators();
  absl::Status LoadEbpf();
  absl::Status RegisterCorrelators();
  absl::Status LoadProbes();
  DataManager data_manager_;
  LogExporterInterface *logger_;
  MetricExporterInterface *metric_exporter_;
  absl::flat_hash_map<std::string, std::shared_ptr<Source>> sources_;
  ebpf_monitor::MapSource map_source_;
  bool dry_run_;
  absl::flat_hash_map<std::string,
                      std::shared_ptr<CorrelatorInterface>> correlators_;
};

}  // namespace ebpf_monitor
#endif  // _EBPF_MONITOR_H_
