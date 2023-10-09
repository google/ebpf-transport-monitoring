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

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "events.h"
#include "exporters/exporters_util.h"
#include "ebpf_monitor/exporter/data_types.h"
#include "spdlog/fmt/bin_to_hex.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/spdlog.h"

namespace ebpf_monitor {

FileLogger::FileLogger() {
  file_size_ = 1048576 * 50;
  max_files_ = 2;
  directory_ = "/tmp";
}
FileLogger::FileLogger(uint8_t max_files, uint32_t file_size,
                       std::string dir_name)
    : max_files_(max_files), file_size_(file_size), directory_(dir_name) {}

absl::Status FileLogger::Init() {
  spdlog::file_event_handlers handlers;
  logger_ = spdlog::rotating_logger_st("file_logger", directory_ + "/ebpf.txt",
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

FileMetricExporter::FileMetricExporter() {
  file_size_ = 1048576 * 50;
  max_files_ = 2;
  directory_ = "/tmp";
}

FileMetricExporter::FileMetricExporter(uint8_t max_files, uint32_t file_size,
                                       std::string dir_name)
    : max_files_(max_files), file_size_(file_size), directory_(dir_name) {}

absl::Status FileMetricExporter::Init() {
  logger_ = spdlog::rotating_logger_st("file_metric", directory_ + "/ebpf.txt",
                                       file_size_, max_files_);
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
