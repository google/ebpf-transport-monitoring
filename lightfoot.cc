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

#include <string>
#include <cstdint>
#include <thread>
#include <iostream>
#include <ostream>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/base/log_severity.h"
#include "absl/log/globals.h"
#include "absl/log/initialize.h"

#include "absl/status/status.h"
#include "absl/strings/numbers.h"
#include "ebpf_monitor/config_manager/proc_manager.h"
#include "ebpf_monitor/ebpf_monitor.h"
#include "ebpf_monitor/config_manager/k8s_http_handler.h"
#include "ebpf_monitor/config_manager/proc_http_handler.h"
#include "ebpf_monitor/config_manager/config_server.h"

ABSL_FLAG(bool, dry_run, false, "Run without loading eBPF code");
ABSL_FLAG(int, log_level, 3, "Log level (0: INFO, 1: WARNING, 2: ERROR)");
ABSL_FLAG(uint16_t, server_port, 12000,
          "config server port. Set to 0 to disable server");
ABSL_FLAG(std::vector<std::string>, procs, std::vector<std::string>(),
          "Name of processes to trace.");

int main(int argc, char **argv) {
  absl::Status status;

  auto pids_str = absl::ParseCommandLine(argc, argv);
  if (pids_str.empty()){
    std::cerr << "Please provide pids in command line arguments" << std::endl;
    return -1;
  }
  absl::InitializeLog();
  absl::SetStderrThreshold(
      absl::LogSeverityAtLeast(absl::GetFlag(FLAGS_log_level)));
  std::vector<pid_t> pids;
  for (auto pid_str : pids_str) {
    pid_t pid;
    if (absl::SimpleAtoi(pid_str, &pid)) {
      pids.push_back(pid);
    }
  }

  bool dry_run = absl::GetFlag(FLAGS_dry_run);

  status = ebpf_monitor::EbpfMonitor::GetInstance().Init(dry_run);
  if (!status.ok()) {
    std::cerr <<  status.message() << std::endl;
    return -1;
  }

  ebpf_monitor::ProcManager * proc_manager = new ebpf_monitor::ProcManager();
  proc_manager->Init();
  proc_manager->AddPids(pids);
  proc_manager->AddProcesses(absl::GetFlag(FLAGS_procs));
  ebpf_monitor::ConfigServer *server =
      new ebpf_monitor::ConfigServer(absl::GetFlag(FLAGS_server_port));
  ebpf_monitor::K8sHttpHandler *k8s_handler;
  ebpf_monitor::ProcHttpHandler *proc_handler;
  if (absl::GetFlag(FLAGS_server_port) > 0) {
    server->Init();
    std::thread config_server_thread
        (&ebpf_monitor::ConfigServer::Start, server);
    config_server_thread.detach();
    k8s_handler = new ebpf_monitor::K8sHttpHandler(server, proc_manager);
    proc_handler = new ebpf_monitor::ProcHttpHandler(server, proc_manager);
  }

  status = ebpf_monitor::EbpfMonitor::GetInstance().Start();
  if (!status.ok()) {
    std::cerr <<  status.message() << std::endl;
    return -1;
  }

  return 0;
}
