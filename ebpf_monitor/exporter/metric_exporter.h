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

#ifndef _EBPF_MONITOR_EXPORTER_METRIC_EXPORTER_H_
#define _EBPF_MONITOR_EXPORTER_METRIC_EXPORTER_H_

#include <string>

#include "absl/status/status.h"
#include "ebpf_monitor/correlator/correlator.h"
#include "ebpf_monitor/exporter/data_types.h"
#include "ebpf_monitor/exporter/handlers.h"

namespace ebpf_monitor {

class MetricExporterInterface : public MetricHandlerInterface {
 public:
  virtual absl::Status Init() { return absl::OkStatus(); }
  virtual absl::Status RegisterMetric(std::string name,
                                      const MetricDesc& desc) = 0;
  virtual ~MetricExporterInterface() {}
  virtual void RegisterCorrelator(
  std::shared_ptr<CorrelatorInterface> correlator) {
    correlators_.push_back(std::move(correlator));
  }

 protected:
  std::vector<std::shared_ptr<CorrelatorInterface>> correlators_;
};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_EXPORTER_METRIC_EXPORTER_H_
