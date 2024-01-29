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

#include "correlators/h2_go_correlator.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>

#include <vector>
#include <string>
#include <cstdint>
#include <memory>

#include "absl/time/time.h"
#include "absl/time/clock.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/strings/str_format.h"
#include "ebpf_monitor/source/data_ctx.h"
#include "events.h"
#include "ebpf_monitor/correlator/correlator.h"
#include "sources/common/correlator_types.h"

namespace ebpf_monitor {

#define PERF_PAGES 2

absl::StatusOr<std::string> H2GoCorrelator::GetUUID(uint64_t eBPF_conn_id) {
  auto it = connection_map_.find(eBPF_conn_id);
  if (it == connection_map_.end()) {
    return absl::NotFoundError("conn id not registered");
  }
  return connection_map_[eBPF_conn_id];
}

absl::Status H2GoCorrelator::Init() {
  auto it = sources_.find(Layer::kHTTP2);
  if (it == sources_.end()) {
    return absl::NotFoundError("No Http sources found");
  }
  for (auto &source : it->second) {
    auto map = source->GetMap("h2_grpc_correlation");
    if (!map.ok()) {
      return map.status();
    }
    log_sources_.push_back(*map);
    map = source->GetMap("h2_events");
    if (!map.ok()) {
      return map.status();
    }
    log_sources_.push_back(*map);
  }
  it = sources_.find(Layer::kTCP);
  if (it == sources_.end()) {
    return absl::NotFoundError("No TCP sources found");
  }
  for (auto &source : it->second) {
    auto map = source->GetMap("tcp_events");
    if (!map.ok()) {
      return map.status();
    }
    log_sources_.push_back(*map);
  }
  return absl::OkStatus();
}

std::vector<std::shared_ptr<DataCtx>> &H2GoCorrelator::GetLogSources() {
  return log_sources_;
}

std::vector<std::shared_ptr<DataCtx>> &H2GoCorrelator::GetMetricSources() {
  return metric_sources_;
}

absl::flat_hash_map<std::string, std::string> H2GoCorrelator::GetLabels(
    std::string uuid) {
  if (correlator_.find(uuid) == correlator_.end()) {
    return {};
  }
  return {{"pid", std::to_string(correlator_[uuid].pid)}};
}

std::vector<std::string> H2GoCorrelator::GetLabelKeys() { return {{"pid"}}; }

void H2GoCorrelator::HandleNewConnection (const struct ConnInfo *conn_info) {
  if (conn_info->tcp_conn_id != 0 && conn_info->h2_conn_id != 0) {
    connection_map_[conn_info->tcp_conn_id] = conn_info->UUID;
    connection_map_[conn_info->h2_conn_id] = conn_info->UUID;
  }
}

absl::Status H2GoCorrelator::HandleHTTP2(void * data) {
  const correlator_ip_t *const c_data =
      static_cast<const correlator_ip_t *const>(data);
  char local_address[INET6_ADDRSTRLEN];
  char remote_address[INET6_ADDRSTRLEN];

  if ((c_data->llen == 4) &&
      inet_ntop(AF_INET, &c_data->laddr, &local_address[0], INET6_ADDRSTRLEN) ==
          nullptr) {
    return absl::InternalError("Could not convert address");
  }
  if ((c_data->llen == 16) &&
      inet_ntop(AF_INET6, &c_data->laddr, &local_address[0],
                INET6_ADDRSTRLEN) == nullptr) {
    return absl::InternalError("Could not convert address");
  }
  if ((c_data->rlen == 4) &&
      inet_ntop(AF_INET, &c_data->raddr, &remote_address[0],
                INET6_ADDRSTRLEN) == nullptr) {
    return absl::InternalError("Could not convert address");
  }
  if ((c_data->rlen == 16) &&
      inet_ntop(AF_INET6, &c_data->raddr, &remote_address[0],
                INET6_ADDRSTRLEN) == nullptr) {
    return absl::InternalError("Could not convert address");
  }
  std::string key = absl::StrFormat("%s:%d->%s:%d", local_address,
                                    c_data->lport,
                                    remote_address, c_data->rport);
  struct ConnInfo conn_info = {0};
  if (this->correlator_.find(key) == this->correlator_.end()) {
    conn_info.UUID = key;
    conn_info.h2_conn_id = c_data->conn_id;
    conn_info.start_time = absl::Now();
    this->correlator_.insert({key, conn_info});
  } else {
    this->correlator_[key].h2_conn_id = c_data->conn_id;
  }
  conn_info = this->correlator_[key];
  HandleNewConnection(&conn_info);
  return absl::OkStatus();
}

// Since we are using key as uuid this search is easy
bool H2GoCorrelator::CheckUUID(std::string uuid) {
  return correlator_.find(uuid) != correlator_.end();
}

absl::Status H2GoCorrelator::HandleHTTP2Events(void * data) {
  const ec_ebpf_events_t *const event =
      static_cast<const ec_ebpf_events_t *const>(data);
  switch (event->mdata.event_type) {
    case EC_H2_EVENT_CLOSE: {
      for (auto it = correlator_.begin(); it != correlator_.end(); ++it) {
        // TODO: Change the code to add delay to deletion
        if (it->second.h2_conn_id == event->mdata.connection_id) {
          connection_map_.erase(it->second.h2_conn_id);
          connection_map_.erase(it->second.tcp_conn_id);
          correlator_.erase(it);
          break;
        }
      }
    }
  }
  return absl::OkStatus();
}

absl::Status H2GoCorrelator::HandleTCP(void * data) {
  const ec_ebpf_events_t *const event =
      static_cast<const ec_ebpf_events_t *const>(data);
  switch (event->mdata.event_type) {
    case EC_TCP_EVENT_START: {
      char src_address[INET6_ADDRSTRLEN];
      char dest_address[INET6_ADDRSTRLEN];
      const ec_tcp_start_t *start = (const ec_tcp_start_t *)(event->event_info);
      if (inet_ntop(start->family, &start->saddr6, &src_address[0],
                    INET6_ADDRSTRLEN) == nullptr) {
        return absl::InternalError("Invalid ip address");
      }
      if (inet_ntop(start->family, &start->daddr6, &dest_address[0],
                    INET6_ADDRSTRLEN) == nullptr) {
        return absl::InternalError("Invalid ip address");
      }
      std::string key = absl::StrFormat(
          "%s:%d->%s:%d", src_address, start->sport,
          dest_address, start->dport);
      struct ConnInfo conn_info = {0};
      if (this->correlator_.find(key) == this->correlator_.end()) {
        conn_info.UUID = key;
        conn_info.tcp_conn_id = event->mdata.connection_id;
        conn_info.pid = event->mdata.pid;
        conn_info.start_time = absl::Now();
        this->correlator_.insert({key, conn_info});
      } else {
        this->correlator_[key].tcp_conn_id = event->mdata.connection_id;
        this->correlator_[key].pid = event->mdata.pid;
      }
      conn_info = this->correlator_[key];
      HandleNewConnection(&conn_info);
      break;
    }
    case EC_TCP_EVENT_STATE_CHANGE: {
      const ec_tcp_state_change_t *const state_change =
          (const ec_tcp_state_change_t *const)(event->event_info);
      if (state_change->new_state == 7) {  // 7 == TCP_CLOSE
        for (auto it = correlator_.begin(); it != correlator_.end(); ++it) {
          if (it->second.tcp_conn_id == event->mdata.connection_id) {
            connection_map_.erase(it->second.h2_conn_id);
            connection_map_.erase(it->second.tcp_conn_id);
            correlator_.erase(it);
            break;
          }
        }
      }
    }
  }
  return absl::OkStatus();
}

absl::Status H2GoCorrelator::HandleData(absl::string_view log_name,
                                        void * data,
                                        uint32_t size) {
  if (!log_name.compare("h2_grpc_correlation")) {
    return HandleHTTP2(data);
  }
  if (!log_name.compare("h2_grpc_events")) {
    return HandleHTTP2Events(data);
  }
  if (!log_name.compare("tcp_events")) {
    return HandleTCP(data);
  }
  return absl::OkStatus();
}

absl::Status H2GoCorrelator::HandleData(absl::string_view metric_name,
                                        void *key,
                                        void *value) {
  return absl::OkStatus();
}

// This function will delete entries in the cases where the correlation was not
// successful.
void H2GoCorrelator::Cleanup() {
  absl::Time now = absl::Now();
  for (auto it = correlator_.begin(); it != correlator_.end();) {
    if (it->second.h2_conn_id != 0 && it->second.tcp_conn_id != 0 &&
      now - it->second.start_time > absl::Seconds(120)) {
      correlator_.erase(it++);
    } else {
      ++it;
    }
  }
}

}  // namespace ebpf_monitor
