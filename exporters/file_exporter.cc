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

#include "exporters/file_exporter.h"

#include <cstdint>
#include <string>

#include "spdlog/common.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "absl/flags/flag.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "ebpf_monitor/exporter/data_types.h"
#include "events.h"
#include "exporters/exporters_util.h"

ABSL_FLAG(uint32_t, file_log_max_size, 50,
          "Size per file of metrics and logs before rotation (Mb).");
ABSL_FLAG(uint16_t, file_log_num_files, 1,
          "Number of rotated files to create to store logs");
ABSL_FLAG(std::string, file_log_location, "/tmp",
          "Directory to store logs and metrics");

namespace ebpf_monitor {

FileLogger::FileLogger()
    : max_files_(absl::GetFlag(FLAGS_file_log_num_files)),
      file_size_(absl::GetFlag(FLAGS_file_log_max_size) * 1024 * 1024),
      directory_(absl::GetFlag(FLAGS_file_log_location)) {}

absl::Status FileLogger::Init() {
  spdlog::file_event_handlers handlers;
  LOG(INFO) << "Creating file logger" << directory_ + "/logs/ebpf.txt";
  logger_ =
      spdlog::rotating_logger_st("file_logger", directory_ + "/logs/ebpf.txt",
                                 file_size_, max_files_, true, handlers);
  if (logger_ == nullptr) {
    return absl::InternalError("Could not create file logger");
  }
  logger_->set_pattern("%v");
  return absl::OkStatus();
}

absl::Status FileLogger::RegisterLog(std::string name, LogDesc& log_desc) {
  if (logs_.find(name) != logs_.end()) {
    return absl::AlreadyExistsError("log already registered");
  }
  logs_[name] = true;
  return absl::OkStatus();
}

absl::Status FileLogger::HandleData(absl::string_view log_name,
                                    void* data,
                                    uint32_t size) {
  static uint32_t counter;
  absl::Status status;
  if (logs_.find(log_name) == logs_.end()) {
    return absl::NotFoundError("log not registered");
  }
  auto conn_id = GetLogConnId(log_name, data);
  absl::StatusOr<std::string> uuid;
  for (auto& correlator : correlators_) {
    uuid = correlator->GetUUID(conn_id);
    if (uuid.ok()) {
      break;
    }
  }
  if (!uuid.ok()) {
      return absl::OkStatus();
  }
  auto log_data = GetLogString(log_name, *uuid, data);
  if (!log_data.ok()) {
    return log_data.status();
  }
  logger_->info("{}", *log_data);
  if (counter++ > 100) {
    logger_->flush();
    counter = 0;
  }
  return absl::OkStatus();
}

FileMetricExporter::FileMetricExporter()
    : max_files_(absl::GetFlag(FLAGS_file_log_num_files)),
      file_size_(absl::GetFlag(FLAGS_file_log_max_size) * 1024 * 1024),
      directory_(absl::GetFlag(FLAGS_file_log_location)) {}

absl::Status FileMetricExporter::Init() {
  LOG(INFO) << "Creating file metrics Exporter"
            << directory_ + "/metrics/ebpf.txt";
  logger_ = spdlog::rotating_logger_st(
      "file_metric", directory_ + "/metrics/ebpf.txt", file_size_, max_files_);
  if (logger_ == nullptr) {
    return absl::InternalError("Could not create file metric exporter");
  }
  logger_->set_pattern("%v");
  return absl::OkStatus();
}

absl::Status FileMetricExporter::RegisterMetric(std::string name,
                                                const MetricDesc& desc) {
  if (metrics_.find(name) != metrics_.end()) {
    return absl::AlreadyExistsError("metric already registered");
  }
  metrics_[name] = desc;
  return absl::OkStatus();
}

absl::Status FileMetricExporter::HandleData(absl::string_view metric_name,
                                            void* key, void* value) {
  static uint32_t counter;
  auto it = metrics_.find(metric_name);
  if (it == metrics_.end()) {
    return absl::NotFoundError("metric_name not found");
  }
  metric_format_t* metric = (metric_format_t*)value;
  absl::StatusOr<std::string> uuid;
  for (auto& correlator : correlators_) {
    uuid = correlator->GetUUID(*(uint64_t*)key);
    if (uuid.ok()) {
      break;
    }
  }
  if (!uuid.ok()) {
      return absl::OkStatus();
  }
  if (!last_read_.CheckMetricTime(metric_name, *uuid, metric->timestamp).ok()) {
    return absl::OkStatus();
  }
  auto metric_str = GetMetricString(
      metric_name, *uuid, it->second, key, &(metric->data), metric->timestamp);
  if (!metric_str.ok()) {
    return metric_str.status();
  }
  logger_->info("{}", *metric_str);
  if (counter++ > 100) {
    logger_->flush();
    counter = 0;
  }
  return absl::OkStatus();
}

void FileMetricExporter::Cleanup() {
  auto uuids = last_read_.GetUUID();
  bool found;
  for (const auto& uuid : uuids) {
    found = false;
    for (auto& correlator : correlators_) {
      if (correlator->CheckUUID(uuid)) {
        found = true;
        break;
      }
    }
    if (found) continue;
    last_read_.DeleteValue(uuid);
  }
}

}  // namespace ebpf_monitor
