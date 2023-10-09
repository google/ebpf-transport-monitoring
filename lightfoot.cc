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

#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/strings/numbers.h"
#include "correlators/h2_go_correlator.h"
#include "correlators/openssl_correlator.h"
#include "data_manager.h"
#include "ebpf_monitor/correlator/correlator.h"
#include "ebpf_monitor/exporter/log_exporter.h"
#include "ebpf_monitor/exporter/metric_exporter.h"
#include "ebpf_monitor/source/source.h"
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

ABSL_FLAG(bool, dry_run, false, "Run without loading eBPF code");
ABSL_FLAG(bool, extract_source, true, "Extract source from linked tar");
ABSL_FLAG(bool, file_log, false, "Log to file");
ABSL_FLAG(bool, host_agg, false, "Aggregate at host level");
ABSL_FLAG(bool, opencensus_log, false,
          "Use opencensus to export.");
ABSL_FLAG(std::string, gcp_creds, "", "service acoount credentials");
ABSL_FLAG(std::string, gcp_project, "", "gcp project id");
ABSL_FLAG(std::vector<std::string>, custom_labels, std::vector<std::string>(),
          "Labels to attach to opencensus metrics <key>:<value>");

void check_eof(int, short, void *arg) { // NOLINT
  struct event_base *base = static_cast<struct event_base *>(arg);
  char data;
  int size_read = read(0, &data, 1);
  if (size_read == 0) {  // EOF
    event_base_loopexit(base, nullptr);
  }
}

int main(int argc, char **argv) {
  struct event_base *base = event_base_new();
  ebpf_monitor::DataManager data_manager(base);
  ebpf_monitor::LogExporterInterface *logger = nullptr;
  ebpf_monitor::MetricExporterInterface *metric_exporter = nullptr;
  absl::Status status;

  status = data_manager.Init();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }

  auto pids_str = absl::ParseCommandLine(argc, argv);
  if (pids_str.empty()){
    std::cerr << "Please provide pids in command line arguments" << std::endl;
    return -1;
  }

  std::string gcp_creds = absl::GetFlag(FLAGS_gcp_creds);
  std::string gcp_project = absl::GetFlag(FLAGS_gcp_project);

  if (absl::GetFlag(FLAGS_file_log)) {
    logger = new ebpf_monitor::FileLogger(1, 1048576 * 50, "./logs/");
    metric_exporter =
        new ebpf_monitor::FileMetricExporter(1, 1048576 * 50, "./metrics/");
  } else if (absl::GetFlag(FLAGS_opencensus_log)) {
    if (gcp_project.empty()) {
      std::cerr << "GCP project name must be specified" << std::endl;
      return -1;
    }
    ebpf_monitor::AggregationLevel agg =
        ebpf_monitor::AggregationLevel::kConnection;
    if (absl::GetFlag(FLAGS_host_agg)) {
      agg = ebpf_monitor::AggregationLevel::kHost;
    }
    logger = new ebpf_monitor::GCPLogger(gcp_project, gcp_creds);
    auto oc_metric_exporter =
        new ebpf_monitor::OCGCPMetricExporter(gcp_project, gcp_creds, agg);
    metric_exporter = oc_metric_exporter;
    absl::flat_hash_map<std::string, std::string> oc_labels;
    for (const auto& label : absl::GetFlag(FLAGS_custom_labels)) {
      auto pos = label.find(":");
      if (pos == std::string::npos) {
        std::cerr << "Delimter : not found for " << label << std::endl;
        return 0;
      }
      oc_labels.insert(
          {label.substr(0, pos), label.substr(pos + 1, std::string::npos)});
    }
    status = oc_metric_exporter->CustomLabels(oc_labels);
    if (!status.ok()) {
      std::cerr << "Error adding custom labels " << status << std::endl;
      return 0;
    }
  } else {
    logger = new ebpf_monitor::StdoutEventExporter();
    metric_exporter = new ebpf_monitor::StdoutMetricExporter();
  }

  if (logger == nullptr || metric_exporter == nullptr) {
    std::cerr << "Count not create exporters" << std::endl;
    return -1;
  }

  status = logger->Init();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }
  status = metric_exporter->Init();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }

  /* Maps need to be loaded first so that we can share fds*/
  ebpf_monitor::MapSource map_source;
  status = map_source.Init(absl::GetFlag(FLAGS_extract_source));
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }
  const bool dry_run = absl::GetFlag(FLAGS_dry_run);
  if (!dry_run) {
    status = map_source.LoadObj();
    if (!status.ok()) {
      std::cerr << status << std::endl;
      return -1;
    }
    status = map_source.LoadMaps();
    if (!status.ok()) {
      std::cerr << status << std::endl;
      return -1;
    }
  }

  std::vector<std::shared_ptr<ebpf_monitor::Source> > sources;
  auto tcp_source = std::make_shared<ebpf_monitor::TcpSource>();

  auto h2_source = std::make_shared<ebpf_monitor::H2GoGrpcSource>();
  auto openssl_source = std::make_shared<ebpf_monitor::OpenSslSource>();
  std::shared_ptr<ebpf_monitor::H2GoCorrelator> golang_correlator =
      std::make_shared<ebpf_monitor::H2GoCorrelator>();
  sources.emplace_back(h2_source);
  sources.emplace_back(tcp_source);
  golang_correlator->AddSource(ebpf_monitor::Layer::kTCP, tcp_source);
  golang_correlator->AddSource(ebpf_monitor::Layer::kHTTP2, h2_source);

  std::shared_ptr<ebpf_monitor::OpenSslCorrelator> openssl_correlator
      = std::make_shared<ebpf_monitor::OpenSslCorrelator>();
  openssl_correlator->AddSource(ebpf_monitor::Layer::kHTTP2, openssl_source);
  sources.emplace_back(openssl_source);

  std::vector<std::shared_ptr<ebpf_monitor::CorrelatorInterface> > correlators;
  correlators.emplace_back(golang_correlator);
  correlators.emplace_back(openssl_correlator);
  std::vector<pid_t> pids;
  for (auto pid_str : pids_str) {
    pid_t pid;
    if (absl::SimpleAtoi(pid_str, &pid)) {
      pids.push_back(pid);
    }
  }

  for (pid_t pid : pids) {
    status = h2_source->AddPID(pid);
    if (status.ok()) {
      continue;
    }
    status = openssl_source->AddPID(pid);
    if (status.ok()) {
      continue;
    }
    std::cerr << "ERR: Could not find necessary tracepoints for pid "
        << pid << std::endl;
  }

  for (const auto& correlator : correlators) {
    logger->RegisterCorrelator(correlator);
    metric_exporter->RegisterCorrelator(correlator);
  }

  for (const auto& source : sources) {
    status = source->Init(absl::GetFlag(FLAGS_extract_source));
    if (!status.ok()) {
      std::cerr << status << std::endl;
      return -1;
    }
    if (!dry_run) {
      status = source->LoadObj();
      if (!status.ok()) {
        std::cerr << status << std::endl;
        return -1;
      }
      status = source->LoadMaps();
      if (!status.ok()) {
        std::cerr << status << std::endl;
        return -1;
      }
      for (pid_t pid : pids) {
        status = source->FilterPID(pid);
        if (!status.ok()) {
          std::cerr << status << std::endl;
          return -1;
        }
      }
      auto log_sources = source->GetLogSources();
      for (uint32_t i = 0; i < log_sources.size(); i++) {
        if (log_sources[i]->is_internal() == false) {
          status = logger->RegisterLog(std::string(log_sources[i]->get_name()),
                                      log_sources[i]->get_log_desc());
          if (!status.ok()) {
            if (log_sources[i]->is_shared() && !absl::IsAlreadyExists(status)) {
              std::cerr << status << std::endl;
              return -1;
            }
          }
        }
        status = data_manager.Register(log_sources[i]);
        if (!status.ok()) {
          if (log_sources[i]->is_shared() && !absl::IsAlreadyExists(status)){
            std::cerr << status << std::endl;
            return -1;
          }
        }
      }
      auto metric_sources = source->GetMetricSources();
      for (uint32_t i = 0; i < metric_sources.size(); i++) {
        if (metric_sources[i]->is_internal() == false) {
          status = metric_exporter->RegisterMetric(
              std::string(metric_sources[i]->get_name()),
              metric_sources[i]->get_metric_desc());
          if (!status.ok()) {
            if (metric_sources[i]->is_shared() &&
                !absl::IsAlreadyExists(status)){
              std::cerr << status << std::endl;
              return -1;
            }
          }
        }
        status = data_manager.Register(metric_sources[i]);
        if (!status.ok()) {
          std::cerr << status << std::endl;
          return -1;
        }
      }
    }
  }
  data_manager.AddExternalLogHandler(logger);
  data_manager.AddExternalMetricHandler(metric_exporter);
  if (!dry_run) {
    for (const auto &correlator : correlators) {
      status = correlator->Init();
      if (!status.ok()) {
        std::cerr << status << std::endl;
      }
      auto log_sources = correlator->GetLogSources();
      for (auto &source : log_sources) {
        status = data_manager.AddLogHandler(source->get_name(), correlator);
        if (!status.ok()) {
          std::cerr << status << std::endl;
        }
      }
      auto metric_sources = correlator->GetMetricSources();
      for (auto &source : metric_sources) {
        status = data_manager.AddMetricHandler(source->get_name(), correlator);
        if (!status.ok()) {
          std::cerr << status << std::endl;
        }
      }
    }
    // Probes must be loaded after correlator init
    //  so that we don't miss any messages
    for (const auto& source : sources) {
      status = source->LoadProbes();
      if (!status.ok()) {
        std::cerr << status << std::endl;
        return -1;
      }
    }
  }

  struct event *ev;
  ev = event_new(base, STDIN_FILENO, EV_READ | EV_PERSIST, check_eof, base);
  event_add(ev, nullptr);
  event_base_dispatch(base);
  return 0;
}
