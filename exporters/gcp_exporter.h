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

#ifndef _EXPORTERS_GCP_EXPORTER_H_
#define _EXPORTERS_GCP_EXPORTER_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "exporters/exporters_util.h"
#include "google/cloud/logging/logging_service_v2_client.h"
#include "google/cloud/project.h"
#include "ebpf_monitor/exporter/log_exporter.h"
#include "ebpf_monitor/exporter/metric_exporter.h"
#include "ebpf_monitor/exporter/data_types.h"

namespace ebpf_monitor {

class GCPLogger : public LogExporterInterface {
 public:
  GCPLogger() = delete;
  GCPLogger(const std::string& project_name);
  GCPLogger(const std::string& project_name,
            const std::string& service_file_path);
  ~GCPLogger() = default;
  absl::Status Init() override;
  absl::Status RegisterLog(std::string name, LogDesc& log_desc) override;
  absl::Status HandleData(absl::string_view log_name, void* data,
                         uint32_t size) override;

 private:
  std::vector<google::logging::v2::LogEntry> log_entries_;
  absl::flat_hash_map<std::string, bool> logs_;
  google::cloud::Project project_;
  std::string service_file_path_;
  google::api::MonitoredResource monitored_resource_;
  std::unique_ptr<google::cloud::logging::LoggingServiceV2Client> log_client_;
  absl::Time last_log_sent_;
  absl::flat_hash_map<std::string, std::string> labels_;
};

}  // namespace ebpf_monitor

#endif  // _EXPORTERS_GCP_EXPORTER_H_
