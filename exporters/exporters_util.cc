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

#include "exporters/exporters_util.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "events.h"
#include "ebpf_monitor/exporter/data_types.h"


namespace {

using ebpf_monitor::MetricType;

absl::StatusOr<std::string> PrintTcpData(uint32_t event_type,
                                                const void *const event_info) {
  switch (event_type) {
    case EC_TCP_EVENT_START: {
      char src_address[INET6_ADDRSTRLEN];
      char dst_address[INET6_ADDRSTRLEN];
      const ec_tcp_start_t *const start =
          static_cast<const ec_tcp_start_t *>(event_info);

      if ((inet_ntop(start->family, &start->saddr6, &src_address[0],
                     INET6_ADDRSTRLEN) == nullptr) ||
          (inet_ntop(start->family, &start->daddr6, &dst_address[0],
                     INET6_ADDRSTRLEN) == nullptr)) {
        return absl::InternalError("Invalid ip address");
      }
      return absl::StrFormat("s:%s:%d d:%s:%d ", src_address, start->sport,
                             dst_address, start->dport);
    }
    case EC_TCP_EVENT_STATE_CHANGE: {
      const ec_tcp_state_change_t *const state_change =
          static_cast<const ec_tcp_state_change_t *const>(event_info);
      return absl::StrFormat("O: %d N: %d ", state_change->old_state,
                             state_change->new_state);
    }

    case EC_TCP_EVENT_CONGESTION: {
      const ec_tcp_congestion_t *const congestion =
          static_cast<const ec_tcp_congestion_t *>(event_info);
      return absl::StrFormat(
          "received bytes %u sent bytes %u rcv_cwnd %u snd_wnd %u snd_cwnd %u "
          "srtt %u",
          congestion->bytes_received, congestion->bytes_sent,
          congestion->rcv_cwnd, congestion->snd_wnd, congestion->snd_cwnd,
          congestion->srtt);
    }
    // There is no event specific data for following types
    case EC_TCP_EVENT_PACKET_DROP:
    case EC_TCP_EVENT_RESET:
      break;
    case EC_TCP_EVENT_RETRANS:
      return absl::InternalError("Event should not generate Log");
    case EC_TCP_EVENT_MAX:
    default:
      return absl::InternalError("Unknown event type");
  }
  return "";
}

std::string GetEventString(ec_h2_stream_state_t state) {
  switch (state) {
    case EC_H2_STREAM_BEGIN:
      return "Stream Begin";
    case EC_H2_STREAM_END:
      return "Stream End";
    case EC_H2_STREAM_WINDOW_UPDATE:
      return "Window Update";
    case EC_H2_STREAM_RESET:
      return "Stream Reset";
    case EC_H2_STREAM_UNKNOWN:
      return "Unknown";
    case EC_H2_STREAM_MAX:
    default:
      return "";
  }
}

std::string GetDebugHexString(const uint8_t * debug_data, uint32_t length) {
  if (length == 0) return "";
  if (length > EC_MAX_GO_AWAY_DATA_SIZE) return "";
  char str[2*EC_MAX_GO_AWAY_DATA_SIZE + 1];
  char *p = str;
  size_t buffer_size = sizeof(str);
  for (size_t i = 0;  i < length;  ++i) {
    p += absl::SNPrintF(p, (buffer_size - 2 * i), "%02hhx", debug_data[i]);
  }
  return str;
}

absl::StatusOr<std::string> PrintH2Data(uint32_t event_type,
                                        const void *const event_info,
                                        uint32_t length) {
  switch (event_type) {
    case EC_H2_EVENT_START:
      return "New connection found";
    case EC_H2_EVENT_CLOSE:
      return "Connection Closed";
    case EC_H2_EVENT_STREAM_STATE: {
      const ec_h2_state_t *const state =
          static_cast<const ec_h2_state_t *const>(event_info);
      return absl::StrFormat("%s Id: %d  Val: %d", GetEventString(state->state),
                             state->stream_id, state->value);
    }
    case EC_H2_EVENT_GO_AWAY: {
      const ec_h2_go_away_t *const state =
          static_cast<const ec_h2_go_away_t *const>(event_info);
      uint32_t debug_data_size = length - sizeof(ec_h2_go_away_mdata_t);
      return absl::StrFormat(
          "Go Away Last stream: %d  Error: %d Debug_data: %s:%d",
                             state->mdata.last_stream_id,
                             state->mdata.error_code,
                             GetDebugHexString(state->debug_data,
                                               debug_data_size),
                             debug_data_size);
    }
    // There is no event specific data for following types
    case EC_H2_EVENT_WINDOW_UPDATE:
      return "Window update";
      break;
    case EC_H2_EVENT_SETTINGS:
      return "settings";
      break;
    default:
      return absl::InternalError("Unknown event type");
  }
  return "";
}

std::string MetricValue(const void *const data, MetricType type) {
  switch (type) {
    case MetricType::kUint8:
      return absl::StrFormat("%u", *(uint8_t *)data);
    case MetricType::kUint16:
      return absl::StrFormat("%u", *(uint16_t *)data);
    case MetricType::kUint32:
      return absl::StrFormat("%u", *(uint32_t *)data);
    case MetricType::kUint64:
      return absl::StrFormat("%u", *(uint64_t *)data);
    case MetricType::kInt8:
      return absl::StrFormat("%d", *(int8_t *)data);
    case MetricType::kInt16:
      return absl::StrFormat("%d", *(int16_t *)data);
    case MetricType::kInt32:
      return absl::StrFormat("%d", *(int32_t *)data);
    case MetricType::kInt64:
      return absl::StrFormat("%d", *(int64_t *)data);
    case MetricType::kFloat:
      return absl::StrFormat("%f", *(float *)data);
    case MetricType::kDouble:
      return absl::StrFormat("%f", *(double *)data);
    case MetricType::kInternal:
      // This is an error condition for external metrics
      return "";
  }
  return "";
}

}  // namespace

namespace ebpf_monitor {

static constexpr uint64_t kSecToNanosecFactor = 1000 * 1000 * 1000;

/* TODO: GCP only allows BOOL, INT64, DOUBLE, or DISTRIBUTION. At this point
all metrics are uint64_t hence for now we live with this monstrosity*/
int64_t GetMetric(const void *const data, MetricType type) {
  switch (type) {
    case MetricType::kUint8:
      return *(uint8_t *)data;
    case MetricType::kUint16:
      return *(uint16_t *)data;
    case MetricType::kUint32:
      return *(uint32_t *)data;
    case MetricType::kUint64:
      return *(uint64_t *)data;
    case MetricType::kInt8:
      return *(int8_t *)data;
    case MetricType::kInt16:
      return *(int16_t *)data;
    case MetricType::kInt32:
      return *(int32_t *)data;
    case MetricType::kInt64:
      return *(int64_t *)data;
    case MetricType::kFloat:
      return *(float *)data;
    case MetricType::kDouble:
      return *(double *)data;
    case MetricType::kInternal:
      // This is an error condition for external metrics
      return 0;
  }
  return 0;
}

uint64_t GetLogConnId(absl::string_view log_name,
                                     const void *const data) {
  const ec_ebpf_events_t *const events =
      static_cast<const ec_ebpf_events_t *>(data);
  return events->mdata.connection_id;
}

absl::StatusOr<std::string> GetLogString(
    absl::string_view log_name, absl::string_view uuid,
    const void *const data) {
  absl::StatusOr<std::string> event_info;
  const ec_ebpf_events_t *const events =
      static_cast<const ec_ebpf_events_t *>(data);

  switch (events->mdata.event_category) {
    case EC_CAT_TCP:
      event_info = PrintTcpData(events->mdata.event_type, events->event_info);
      if (!event_info.ok()) {
        return event_info;
      }
      break;
    case EC_CAT_HTTP2:
      event_info = PrintH2Data(events->mdata.event_type, events->event_info,
                               events->mdata.length);
      if (!event_info.ok()) {
        return event_info;
      }
      break;
    default:
      return absl::UnimplementedError("event category not known");
  }
  return absl::StrFormat(
      "%s, %s, timestamp %lu, conn_id %d, pid %d %s %s", log_name, uuid,
      events->mdata.timestamp, events->mdata.connection_id, events->mdata.pid,
      events->mdata.sent_recv == 1 ? "recv" : "sent", *event_info);
}

absl::StatusOr<std::string> GetMetricString(
    absl::string_view name, absl::string_view uuid, const MetricDesc &desc,
    const void *const key, const void *const value, uint64_t timestamp) {
  std::string time_str = absl::FormatTime("%Y-%m-%d %H:%M:%S",
                                          GetTimeFromBPFns(timestamp),
                                          absl::LocalTimeZone());
  return absl::StrFormat(
      "%s,%s,%s,%s:%s%s", uuid, name, time_str, MetricValue(key, desc.key_type),
      MetricValue(value, desc.value_type), GetUnitString(desc.unit));
}

/*In ebpf space we get Monotonic time, convert it to epoch time.*/
absl::Time GetTimeFromBPFns(uint64_t timestamp) {
  struct timespec time, real_time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  clock_gettime(CLOCK_REALTIME, &real_time);

  uint64_t mono_time_val = kSecToNanosecFactor * time.tv_sec + time.tv_nsec;
  uint64_t real_time_val =
      kSecToNanosecFactor * real_time.tv_sec + real_time.tv_nsec;

  return absl::FromUnixNanos(real_time_val - mono_time_val + timestamp);
}

absl::Time GetLogTime(absl::string_view log_name,
                                     const void *const data) {
  const ec_ebpf_events_t *const events =
      static_cast<const ec_ebpf_events_t *>(data);
  return GetTimeFromBPFns(events->mdata.timestamp);
}

absl::StatusOr<uint64_t> MetricTimeChecker::CheckMetricTime(
  absl::string_view metric_name, absl::string_view uuid, uint64_t timestamp) {
  if (timestamp == 0) {
    return absl::InternalError("Collection not started");
  }

  uuids_.insert(std::string(uuid));

  auto timestamp_it = last_read_.find(metric_name);
  if (timestamp_it == last_read_.end()) {
    last_read_[metric_name][uuid] = timestamp;
    // returning a dummy value for the first time
    start_read_[metric_name][uuid] = absl::ToUnixNanos(
        GetTimeFromBPFns(timestamp - kSecToNanosecFactor));
    return start_read_[metric_name][uuid];
  } else if (timestamp_it->second.find(uuid) == (timestamp_it->second.end())) {
    last_read_[metric_name][uuid] = timestamp;
    // returning a dummy value for the first time
    start_read_[metric_name][uuid] = absl::ToUnixNanos(
        GetTimeFromBPFns(timestamp - kSecToNanosecFactor));
    return start_read_[metric_name][uuid];
  } else if (last_read_[metric_name][uuid] >= timestamp) {
    // This section makes sure the last recoded value is sent for continuous
    // reporting
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    uint64_t mono_time_val = kSecToNanosecFactor * time.tv_sec + time.tv_nsec;
    uint64_t old_timestamp = last_read_[metric_name][uuid];
    // Sometimes the same value is sent twice in quick succession.
    // Make sure there is at least 1 second between the times.
    if (mono_time_val - old_timestamp > kSecToNanosecFactor) {
      last_read_[metric_name][uuid] = mono_time_val;
      return old_timestamp;
    }
  } else if (last_read_[metric_name][uuid] < timestamp &&
            (timestamp - last_read_[metric_name][uuid]) > kSecToNanosecFactor) {
    uint64_t old_timestamp = last_read_[metric_name][uuid];
    last_read_[metric_name][uuid] = timestamp;
    return old_timestamp;
  }
  return absl::UnknownError("");
}

absl::StatusOr<uint64_t> MetricTimeChecker::GetMetricStartTime(
    absl::string_view metric_name, absl::string_view uuid) {
  auto timestamp_it = start_read_.find(metric_name);
  if (timestamp_it != start_read_.end()) {
    if (timestamp_it->second.find(uuid) != (timestamp_it->second.end())) {
      return start_read_[metric_name][uuid];
    }
  }
  return absl::UnknownError("");
}

void MetricTimeChecker::DeleteValue(absl::string_view uuid) {
  for (auto it = start_read_.begin(); it != start_read_.end(); it++) {
    it->second.erase(uuid);
  }
  for (auto it = last_read_.begin(); it != start_read_.end(); it++) {
    it->second.erase(uuid);
  }
  uuids_.erase(uuid);
}

absl::flat_hash_set<std::string> MetricTimeChecker::GetUUID() { return uuids_; }

absl::StatusOr<uint64_t> MetricTimeChecker::GetMetricTime(
    absl::string_view metric_name, absl::string_view uuid) {
  auto timestamp_it = start_read_.find(metric_name);
  if (timestamp_it != start_read_.end()) {
    if (timestamp_it->second.find(uuid) != (timestamp_it->second.end())) {
      return last_read_[metric_name][uuid];
    }
  }
  return absl::UnknownError("");
}

uint64_t MetricDataMemory::StoreAndGetValue(absl::string_view metric_name,
                                            absl::string_view uuid,
                                            uint64_t data) {
  auto data_it = data_memory_.find(metric_name);
  uuids_.insert(std::string(uuid));
  if (data_it == data_memory_.end()) {
    data_memory_[metric_name][uuid] = data;
    return 0;
  } else if (data_it->second.find(uuid) == (data_it->second.end())) {
    data_memory_[metric_name][uuid] = data;
    return 0;
  } else {
    auto old_data = data_memory_[metric_name][uuid];
    data_memory_[metric_name][uuid] = data;
    return old_data;
  }
  return 0;
}

void MetricDataMemory::DeleteValue(absl::string_view uuid) {
  for (auto it = data_memory_.begin(); it != data_memory_.end(); it++) {
    it->second.erase(uuid);
  }
  uuids_.erase(uuid);
}

absl::flat_hash_set<std::string> MetricDataMemory::GetUUID() { return uuids_; }

}  // namespace ebpf_monitor
