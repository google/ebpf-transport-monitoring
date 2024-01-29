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
#include "ebpf_monitor/ebpf_monitor.h"

#include <string>
#include <memory>
#include <cstdint>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "correlators/h2_go_correlator.h"
#include "correlators/openssl_correlator.h"
#include "ebpf_monitor/utils/event_manager.h"
#include "ebpf_monitor/data_manager.h"
#include "ebpf_monitor/correlator/correlator.h"
#include "ebpf_monitor/exporter/log_exporter.h"
#include "ebpf_monitor/exporter/metric_exporter.h"
#include "exporters/file_exporter.h"
#include "exporters/gcp_exporter.h"
#include "exporters/oc_gcp_exporter.h"
#include "exporters/stdout_event_logger.h"
#include "exporters/stdout_metric_exporter.h"
#include "sources/source_manager/h2_go_grpc_source.h"
#include "sources/source_manager/map_source.h"
#include "sources/source_manager/openssl_source.h"
#include "sources/source_manager/tcp_source.h"
#include "event2/event.h"
#include "event2/thread.h"

#define EBPF_TM_RETURN_IF_ERROR(cmd) \
  {absl::Status status = cmd;       \
  if (!status.ok()) {        \
    return status;           \
  }}

ABSL_FLAG(bool, extract_source, true, "Extract source from linked tar");
ABSL_FLAG(bool, file_log, false, "Log to file");
ABSL_FLAG(bool, host_agg, false, "Aggregate at host level");
ABSL_FLAG(bool, stdin_eof, true, "Exit on EOF on stdin.");
ABSL_FLAG(bool, opencensus_log, false,
          "Use opencensus to export.");
ABSL_FLAG(std::string, gcp_creds, "", "service acoount credentials");
ABSL_FLAG(std::string, gcp_project, "", "gcp project id");
ABSL_FLAG(std::vector<std::string>, custom_labels, std::vector<std::string>(),
          "Labels to attach to opencensus metrics <key>:<value>");

namespace ebpf_monitor{

EbpfMonitor::EbpfMonitor(): data_manager_(),
      logger_(nullptr),
      metric_exporter_(nullptr) {
}

absl::Status EbpfMonitor::MapSourceInit(){
  /* Maps need to be loaded first so that we can share fds*/
  if (!dry_run_) {
    EBPF_TM_RETURN_IF_ERROR(
      map_source_.Init(absl::GetFlag(FLAGS_extract_source)));
    EBPF_TM_RETURN_IF_ERROR(map_source_.LoadObj());
    EBPF_TM_RETURN_IF_ERROR(map_source_.LoadMaps());
  }
  return absl::OkStatus();
}

absl::Status EbpfMonitor::CreateLoggers() {
  if (absl::GetFlag(FLAGS_file_log)) {
    logger_ = new ebpf_monitor::FileLogger(1, 1048576 * 50, "./logs/");
    metric_exporter_ =
        new ebpf_monitor::FileMetricExporter(1, 1048576 * 50, "./metrics/");
    return absl::OkStatus();
  } else if (absl::GetFlag(FLAGS_opencensus_log)) {
    std::string gcp_creds = absl::GetFlag(FLAGS_gcp_creds);
    std::string gcp_project = absl::GetFlag(FLAGS_gcp_project);
    if (gcp_project.empty()) {
      return absl::InvalidArgumentError("GCP project name must be specified");
    }
    ebpf_monitor::AggregationLevel agg =
        ebpf_monitor::AggregationLevel::kConnection;
    if (absl::GetFlag(FLAGS_host_agg)) {
      agg = ebpf_monitor::AggregationLevel::kHost;
    }
    logger_ = new ebpf_monitor::GCPLogger(gcp_project, gcp_creds);
    auto oc_metric_exporter =
        new ebpf_monitor::OCGCPMetricExporter(gcp_project, gcp_creds, agg);
    metric_exporter_ = oc_metric_exporter;
    absl::flat_hash_map<std::string, std::string> oc_labels;
    for (const auto& label : absl::GetFlag(FLAGS_custom_labels)) {
      auto pos = label.find(":");
      if (pos == std::string::npos) {
        return absl::InvalidArgumentError(
            absl::StrCat("Delimter : not found for", label));
      }
      oc_labels.insert(
          {label.substr(0, pos), label.substr(pos + 1, std::string::npos)});
    }
    EBPF_TM_RETURN_IF_ERROR(oc_metric_exporter->CustomLabels(oc_labels));
    return absl::OkStatus();
  }

  // Default case
  logger_ = new ebpf_monitor::StdoutEventExporter();
  metric_exporter_ = new ebpf_monitor::StdoutMetricExporter();
  return absl::OkStatus();
}

void EbpfMonitor::CreateSourcesCorrelators(){
  sources_.insert({"tcp", std::make_shared<ebpf_monitor::TcpSource>()});
  sources_.insert({"h2_golang",
                   std::make_shared<ebpf_monitor::H2GoGrpcSource>()});
  sources_.insert({"openssl", std::make_shared<ebpf_monitor::OpenSslSource>()});
  correlators_["h2_golang"] =
      std::make_shared<ebpf_monitor::H2GoCorrelator>();
  correlators_["h2_golang"]->AddSource(ebpf_monitor::Layer::kTCP,
                                       sources_["tcp"]);
  correlators_["h2_golang"]->AddSource(ebpf_monitor::Layer::kHTTP2,
                                       sources_["h2_golang"]);

  correlators_["openssl"] = std::make_shared<ebpf_monitor::OpenSslCorrelator>();
  correlators_["openssl"]->AddSource(ebpf_monitor::Layer::kHTTP2,
                                     sources_["openssl"]);
  correlators_["openssl"]->AddSource(ebpf_monitor::Layer::kTCP,
                                    sources_["tcp"]);
  for (const auto& iter : correlators_) {
    logger_->RegisterCorrelator(iter.second);
    metric_exporter_->RegisterCorrelator(iter.second);
  }
}

absl::Status EbpfMonitor::Init(bool dry_run){
  dry_run_ = dry_run;
  if (evthread_use_pthreads() != 0) {
    return absl::InternalError("events with threading not supported.");
  }
  EBPF_TM_RETURN_IF_ERROR(data_manager_.Init());
  EBPF_TM_RETURN_IF_ERROR(CreateLoggers());
  EBPF_TM_RETURN_IF_ERROR(logger_->Init());
  EBPF_TM_RETURN_IF_ERROR(metric_exporter_->Init());
  data_manager_.AddExternalLogHandler(logger_);
  data_manager_.AddExternalMetricHandler(metric_exporter_);
  CreateSourcesCorrelators();
  EBPF_TM_RETURN_IF_ERROR(MapSourceInit());
  EBPF_TM_RETURN_IF_ERROR(LoadEbpf());
  EBPF_TM_RETURN_IF_ERROR(RegisterCorrelators());
  return absl::OkStatus();
}

absl::Status EbpfMonitor::LoadEbpf() {
  absl::Status status;
  for (auto iter = sources_.begin(); iter != sources_.end(); ++iter) {
    if (!dry_run_) {
      EBPF_TM_RETURN_IF_ERROR(
          iter->second->Init(absl::GetFlag(FLAGS_extract_source)));
      EBPF_TM_RETURN_IF_ERROR(iter->second->LoadObj());
      EBPF_TM_RETURN_IF_ERROR(iter->second->LoadMaps());

      auto log_sources = iter->second->GetLogSources();
      for (uint32_t i = 0; i < log_sources.size(); i++) {
        if (log_sources[i]->is_internal() == false) {
          status = logger_->RegisterLog(std::string(log_sources[i]->get_name()),
                                      log_sources[i]->get_log_desc());
          if (!status.ok()) {
            if (log_sources[i]->is_shared() && !absl::IsAlreadyExists(status)) {
              return status;
            }
          }
        }
        status = data_manager_.Register(log_sources[i]);
        if (!status.ok()) {
          if (log_sources[i]->is_shared() && !absl::IsAlreadyExists(status)){
            return status;
          }
        }
      }
      auto metric_sources = iter->second->GetMetricSources();
      for (uint32_t i = 0; i < metric_sources.size(); i++) {
        if (metric_sources[i]->is_internal() == false) {
          status = metric_exporter_->RegisterMetric(
              std::string(metric_sources[i]->get_name()),
              metric_sources[i]->get_metric_desc());
          if (!status.ok()) {
            if (metric_sources[i]->is_shared() &&
                !absl::IsAlreadyExists(status)){
              return status;
            }
          }
        }
        EBPF_TM_RETURN_IF_ERROR(data_manager_.Register(metric_sources[i]));
      }
    }
  }
  return absl::OkStatus();
}

absl::Status EbpfMonitor::RegisterCorrelators(){
  if (!dry_run_) {
    for (const auto &iter : correlators_) {
      EBPF_TM_RETURN_IF_ERROR(iter.second->Init());
      auto log_sources = iter.second->GetLogSources();
      for (auto &source : log_sources) {
        EBPF_TM_RETURN_IF_ERROR(data_manager_.AddLogHandler(source->get_name(),
                                                           iter.second));
      }
      auto metric_sources = iter.second->GetMetricSources();
      for (auto &source : metric_sources) {
        EBPF_TM_RETURN_IF_ERROR(
            data_manager_.AddMetricHandler(source->get_name(), iter.second));
      }
    }
  }
  return absl::OkStatus();
}

absl::Status EbpfMonitor::LoadProbes(){
  for (const auto& it : sources_) {
    EBPF_TM_RETURN_IF_ERROR(it.second->LoadProbes());
  }
  return absl::OkStatus();
}

void CheckEOF(int, short, void *arg) { // NOLINT
  struct event_base *base = static_cast<struct event_base *>(arg);
  char data;
  int size_read = read(0, &data, 1);
  if (size_read == 0) {  // EOF
    event_base_loopexit(base, nullptr);
  }
}

absl::Status EbpfMonitor::Start(){
  struct event *ev;
  auto base = EventManager::GetInstance().event_base();
  if (absl::GetFlag(FLAGS_stdin_eof)) {
    ev = event_new(base, STDIN_FILENO, EV_READ | EV_PERSIST, CheckEOF, base);
    event_add(ev, nullptr);
  }
  if (!dry_run_) {
    EBPF_TM_RETURN_IF_ERROR(LoadProbes());
  }
  EventManager::GetInstance().Start();
  return absl::OkStatus();  // To keep compiler happy
}

absl::Status EbpfMonitor::Monitor(pid_t pid){
  auto status = sources_["tcp"]->AddPID(pid);
  if (!status.ok()) {
    return status;
  }
  status = sources_["h2_golang"]->AddPID(pid);
  if (status.ok()) {
    return absl::OkStatus();
  }
  // Note that this line executes when the above statement fails.
  status = sources_["openssl"]->AddPID(pid);
  if (status.ok()) {
    return absl::OkStatus();
  }
  return absl::InternalError("Could not find tracepoints");
}


absl::Status EbpfMonitor::StopMonitoring(pid_t pid){
  /* The code below is ordered as tcp source is installed for all pids.
  The other sources are installed for only specific pid hence we remove the 
  pid from each source succesively till one of the returns true in which case
  we don't have to do go through any othe sources.*/
  auto status = sources_["tcp"]->RemovePID(pid);
  if (!status.ok()) {
    return status;
  }
  status = sources_["h2_golang"]->RemovePID(pid);
  if (status.ok()) {
    return absl::OkStatus();
  }
  // Note that this line executes when the above statement fails.
  status = sources_["openssl"]->RemovePID(pid);
  if (status.ok()) {
    return absl::OkStatus();
  }
  return absl::InternalError("Could not find tracepoints");
}
}  // namespace ebpf_monitor
