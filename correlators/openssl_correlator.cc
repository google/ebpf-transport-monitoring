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

#include "correlators/openssl_correlator.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <string>
#include <iostream>
#include <memory>
#include <vector>
#include <cstdint>

#include "absl/log/log.h"
#include "absl/time/time.h"
#include "absl/time/clock.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "sources/common/correlator_types.h"
#include "events.h"
#include "ebpf_monitor/correlator/correlator.h"
#include "ebpf_monitor/utils/event_manager.h"
#include "event2/event.h"

namespace ebpf_monitor {

#define PERF_PAGES 2

absl::Status OpenSslCorrelator::Init() {
  auto it = sources_.find(Layer::kTCP);
  if (it == sources_.end()) {
    return absl::NotFoundError("No Tcp sources found");
  }
  for (auto &source : it->second) {
    auto map = source->GetMap("tcp_events");
    if (!map.ok()) {
      return map.status();
    }
    log_sources_.push_back(*map);
  }

  it = sources_.find(Layer::kHTTP2);
  if (it == sources_.end()) {
    return absl::NotFoundError("No Http sources found");
  }
  for (auto &source : it->second) {
    auto map = source->GetMap("openssl_correlation_events");
    if (!map.ok()) {
      return map.status();
    }
    log_sources_.push_back(*map);
  }

  auto map = sources_[Layer::kHTTP2][0]->GetMap("data_sample_cntl");
  if (!map.ok()) {
    return map.status();
  }
  data_cntl_map_ = *map;
  return absl::OkStatus();
}

absl::StatusOr<std::string> OpenSslCorrelator::GetUUID(uint64_t eBPF_conn_id) {
  auto it = connection_map_.find(eBPF_conn_id);
  if (it == connection_map_.end()) {
    return absl::NotFoundError("conn id not registered");
  }
  return connection_map_[eBPF_conn_id];
}

std::vector<std::shared_ptr<DataCtx>> &OpenSslCorrelator::GetLogSources() {
  return log_sources_;
}

std::vector<std::shared_ptr<DataCtx>> &OpenSslCorrelator::GetMetricSources() {
  return metric_sources_;
}

bool OpenSslCorrelator::CheckUUID(std::string uuid) {
  for (const auto& pair : connection_map_) {
    if (pair.second == uuid) {
      return true;
    }
  }
  return false;
}

/* This function is called 15 seconds after a new connection is detected,
 ideally in which time we should have finished correlation and we stop collecting
 correlation information. */
void OpenSslCorrelator::HandleCleanup(evutil_socket_t, short, void *arg) { // NOLINT
  DeleteCtx *dctx = static_cast<DeleteCtx *>(arg);
  auto status = dctx->self->data_cntl_map_->DeleteMapEntry(&dctx->ptr);
  if (!status.ok()) {
    std::cerr << status << std::endl;
  }
  LOG(INFO) << "Erasing context " << dctx->ptr;
  dctx->self->tcp_conn_ctx_.erase(dctx->ptr);
  delete dctx;
}

void OpenSslCorrelator::AddEvent (uint64_t ptr){
  DeleteCtx *dctx = new DeleteCtx();
  dctx->self = this;
  dctx->ptr = ptr;
  auto event = event_new(EventManager::GetInstance().event_base(),
                    -1, 0, &OpenSslCorrelator::HandleCleanup, (void *)dctx);
  // We will stop collecting tls hash data after 15 seconds.
  auto timeval = absl::ToTimeval(absl::Seconds(15));
  event_add(event, &timeval);
}

void OpenSslCorrelator::HandleNewConnection (const struct ConnInfo *conn_info) {
  if (conn_info->tcp_conn_id != 0 && conn_info->h2_conn_id != 0) {
    connection_map_[conn_info->tcp_conn_id] = conn_info->UUID;
    connection_map_[conn_info->h2_conn_id] = conn_info->UUID;
    LOG(INFO)  << "Openssl Correlation " << conn_info->h2_conn_id << " "
        << conn_info->tcp_conn_id << std::endl;
  }
}

absl::Status OpenSslCorrelator::HandleCorrelation(void * data) {
  const openssl_correlation *const c_data =
      static_cast<const openssl_correlation *const>(data);
  uint8_t enable = 1;
  if (c_data->mdata.type == kSslNewConnection){
    LOG(INFO) << "Adding new connection " << c_data->mdata.conn_id;
    AddEvent(c_data->mdata.conn_id);
    return data_cntl_map_->AddMapEntry(&c_data->mdata.conn_id, &enable);
  }
  if (c_data->mdata.type == kSslCorrelationInfo) {
    data_sample_t * sample = (data_sample_t *)(c_data->info);
    if (sample->level == OPENSSL_LEVEL){
      lru_.Add(sample->data, c_data->mdata.conn_id);
    } else {
      auto ssl_ptr = lru_.Get(sample->data);
      if (!ssl_ptr.ok()) {
        return absl::OkStatus();
      }
      auto it = tcp_conn_ctx_.find(c_data->mdata.conn_id);
      if (it == tcp_conn_ctx_.end()) {
        return absl::OkStatus();
      }
      auto uuid = it->second;
      if (correlator_[uuid].h2_conn_id != 0
          && correlator_[uuid].h2_conn_id != *ssl_ptr){
        std::cerr << "Possible collision" << std::endl;
        return absl::OkStatus();
      }
      if (correlator_[uuid].h2_conn_id == 0 ||
         ((correlator_[uuid].h2_conn_id == *ssl_ptr) &&
          correlator_[uuid].count < 3)) {
        correlator_[uuid].h2_conn_id = *ssl_ptr;
        correlator_[uuid].count++;
      }
      if  (correlator_[uuid].count == 3) {
        HandleNewConnection(&correlator_[uuid]);
        correlator_[uuid].count++;
      }
    }
  }
  return absl::OkStatus();
}


absl::Status OpenSslCorrelator::HandleTCP(void * data) {
  const ec_ebpf_events_t *const event =
      static_cast<const ec_ebpf_events_t *const>(data);
  LOG(INFO) << "HandleTCP " << event->mdata.event_type
      << " " << event->mdata.connection_id;
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
      conn_info.start_time = absl::Now();
      conn_info.UUID = key;
      conn_info.tcp_conn_id = event->mdata.connection_id;
      conn_info.pid = event->mdata.pid;
      conn_info.h2_conn_id = 0;
      conn_info.count = 0;
      this->correlator_.insert({key, conn_info});
      conn_info = this->correlator_[key];
      auto status = data_cntl_map_->AddMapEntry(&conn_info.tcp_conn_id,
                                           &conn_info.pid);
      if (!status.ok()) {
        return status;
      }
      AddEvent(conn_info.tcp_conn_id);
      tcp_conn_ctx_.insert({conn_info.tcp_conn_id, conn_info.UUID});
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
      break;
    }
    default:
      break;
  }
  return absl::OkStatus();
}

absl::Status OpenSslCorrelator::HandleData(absl::string_view log_name,
                                        void * data,
                                        uint32_t size) {
  if (!log_name.compare("openssl_correlation_events")) {
    return HandleCorrelation(data);
  }
  if (!log_name.compare("tcp_events")) {
    return HandleTCP(data);
  }
  return absl::OkStatus();
}

void OpenSslCorrelator::Cleanup() {
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
