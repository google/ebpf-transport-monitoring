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

#include "exporters/gcp_exporter.h"

#include <fstream>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "absl/time/time.h"
#include "exporters/exporters_util.h"
#include "exporters/gce_metadata.h"
#include "google/cloud/credentials.h"
#include "google/cloud/logging/logging_service_v2_client.h"
#include "google/cloud/project.h"
#include "google/cloud/status.h"
#include "ebpf_monitor/exporter/data_types.h"

constexpr absl::Duration LOGGING_INTERVAL = absl::Minutes(1);
constexpr uint32_t LOGS_PER_REQUEST = 199;

namespace {

google::api::MonitoredResource CreateMontioredResource(
    const std::string& project_id) {
  google::api::MonitoredResource resource;
  auto labels = *resource.mutable_labels();
  resource.set_type("global");
  labels["project_id"] = project_id;
  return resource;
}

}  // namespace

namespace ebpf_monitor {

namespace logging = ::google::cloud::logging;

constexpr char kCloudLoggingPathTemplate[] = "projects/$0/logs/";
constexpr char kMetricTypePrefix[] = "custom.googleapis.com";

GCPLogger::GCPLogger(const std::string& project_name) : project_(project_name) {
  monitored_resource_ = CreateMontioredResource(project_.FullName());
}

GCPLogger::GCPLogger(const std::string& project_name,
                     const std::string& service_file_path)
    : project_(project_name), service_file_path_(service_file_path) {
  monitored_resource_ = CreateMontioredResource(project_.FullName());
}

absl::Status GCPLogger::Init() {
  if (service_file_path_.empty()) {
    log_client_ = std::make_unique<logging::LoggingServiceV2Client>(
        logging::MakeLoggingServiceV2Connection());
  } else {
    auto creds = std::ifstream(service_file_path_);
    if (!creds.is_open()) {
      return absl::NotFoundError("Service file creds cannot be opened");
    }
    auto contents =
        std::string(std::istreambuf_iterator<char>(creds.rdbuf()), {});
    auto options =
        google::cloud::Options{}.set<google::cloud::UnifiedCredentialsOption>(
            google::cloud::MakeServiceAccountCredentials(contents));

    log_client_ = std::make_unique<logging::LoggingServiceV2Client>(
        logging::MakeLoggingServiceV2Connection(options));
    last_log_sent_ = absl::Now();
  }

  auto metadata = GCEMetadata::GetGCEMetadata();
  if (metadata.ok()) {
    labels_ = *metadata;
  } else {
    char hostname[HOST_NAME_MAX];
    int err = gethostname(hostname, HOST_NAME_MAX);
    if (err != 0) {
      return absl::InternalError(
          absl::StrFormat("gethostname failed with %d", errno));
    }
    labels_["hostname"] = hostname;
  }
  return absl::OkStatus();
}

absl::Status GCPLogger::RegisterLog(std::string name, LogDesc& log_desc) {
  if (logs_.find(name) != logs_.end()) {
    return absl::AlreadyExistsError("log already registered");
  }
  logs_[name] = true;
  return absl::OkStatus();
}

absl::Status GCPLogger::HandleData(absl::string_view log_name,
                                  void* data, uint32_t size) {
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
  auto log_entry = google::logging::v2::LogEntry();
  *log_entry.mutable_resource() = monitored_resource_;
  auto log_time = GetLogTime(log_name, data);
  auto timestamp = log_entry.mutable_timestamp();
  const int64_t sec = absl::ToUnixSeconds(log_time);
  timestamp->set_seconds(sec);
  timestamp->set_nanos((log_time - absl::FromUnixSeconds(sec)) /
                       absl::Nanoseconds(1));
  log_entry.set_severity(google::logging::type::LogSeverity::INFO);
  log_entry.set_text_payload(*log_data);
  log_entries_.emplace_back(log_entry);
  // TODO: This should Ideally be done as async but for now so we let it be.
  if (log_entries_.size() > LOGS_PER_REQUEST ||
      (absl::Now() - last_log_sent_) > LOGGING_INTERVAL) {
    std::map<std::string, std::string> labels;
    labels["source"] = "ebpf";
    for (auto& label : labels_) {
      labels[label.first] = labels[label.second];
    }
    last_log_sent_ = absl::Now();
    auto response = log_client_->WriteLogEntries(
        absl::StrCat(
            absl::Substitute(kCloudLoggingPathTemplate, project_.project_id()),
            "ebpf_prober"),
        monitored_resource_, labels, log_entries_);
    log_entries_.clear();
    if (!response.ok()) {
      return absl::InternalError(response.status().message());
    }
  }
  return absl::OkStatus();
}

}  // namespace ebpf_monitor
