#ifndef _PARSE_H2_FRAME_H_
#define _PARSE_H2_FRAME_H_

#ifdef CORE
#include "vmlinux.h"
#else
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/types.h>
#endif

#include "bpf/bpf_endian.h"
#include "bpf/bpf_tracing.h"
#include "defines.h"
#include "events.h"
#include "h2_symaddrs.h"
#include "maps.h"
#include "sym_addrs.h"
#include "sym_helpers.h"

static __always_inline int send_h2_headers(void *ctx, ec_ebpf_events_t *event,
                                           uint32_t stream_id) {
  uint64_t timestamp = event->mdata.timestamp;
  uint64_t stream_hash = stream_id;
  stream_hash =
      (stream_hash << 48) | (event->mdata.connection_id & 0xffffffffffff);

  uint64_t *value =
      (uint64_t *)bpf_map_lookup_elem(&h2_stream_id, &stream_hash);
  if (value == NULL) {
    bpf_map_update_elem(&h2_stream_id, &stream_hash, &timestamp, BPF_NOEXIST);
  }
  return 0;
}

static __always_inline int send_h2_end(void *ctx, ec_ebpf_events_t *event,
                                       uint32_t stream_id) {
  // There is a potential race condition here. So maybe spinlocks is the answer
  // But spinlocks are available only from 5.1. We will accept a
  // small difference in count for now.
  uint64_t stream_hash = stream_id;
  stream_hash =
      (stream_hash << 48) | (event->mdata.connection_id & 0xffffffffffff);
  uint64_t *hash = (uint64_t *)bpf_map_lookup_elem(&h2_stream_id, &stream_hash);
  if (hash == NULL) {
    return 0;
  }

  bpf_map_delete_elem(&h2_stream_id, &stream_hash);
  uint64_t conn_id = event->mdata.connection_id;
  metric_format_t *value =
      (metric_format_t *)bpf_map_lookup_elem(&h2_stream_count, &conn_id);
  if (unlikely(value == NULL)) {
    return 0;
  }
  value->timestamp = event->mdata.timestamp;

  __sync_add_and_fetch(&value->data, 1);

  return 0;
}

static __always_inline void send_h2_ping(void *ctx, ec_ebpf_events_t *event,
                                         void *frame_ptr) {
  uint64_t conn_id = event->mdata.connection_id;
  metric_format_t *value = bpf_map_lookup_elem(&h2_ping_counter, &conn_id);
  if (unlikely(value == NULL)) {
    metric_format_t format = {.timestamp = 0, .data = 1};
    bpf_map_update_elem(&h2_ping_counter, &conn_id, (void *)&format,
                        BPF_NOEXIST);
    return;
  }
  value->timestamp = event->mdata.timestamp;
  __sync_add_and_fetch(&value->data, 1);
}

static __always_inline int send_h2_reset(void *ctx, ec_ebpf_events_t *event,
                                         uint32_t stream_id, uint32_t error) {
  uint64_t conn_id = event->mdata.connection_id;
  metric_format_t *value =
      (metric_format_t *)bpf_map_lookup_elem(&h2_reset_stream_count, &conn_id);
  if (unlikely(value == NULL)) {
    return 0;
  }
  value->timestamp = event->mdata.timestamp;
  value->data += 1;

  send_h2_end(ctx, event, stream_id);
  return 0;
}

static __always_inline int parse_h2_frame(void *ctx, char *buf_ptr,
                                          uint32_t len, ec_ebpf_events_t *event,
                                          bool client) {
  // char fmt[] = "%d %d %d";
  int curr_loc = 0;
  uint32_t frame_length;
  int success;
  if (bpf_probe_read(&frame_length, 4, &buf_ptr[curr_loc])) {
    return -1;
  }

  frame_length = bpf_ntohl(frame_length);
  frame_length >>= 8;
  curr_loc += 3;

  uint8_t frame_type;
  if (unlikely(bpf_probe_read(&frame_type, 1, &buf_ptr[curr_loc]))) {
    return -1;
  }

  curr_loc++;
  uint8_t frame_flags;
  if (unlikely(bpf_probe_read(&frame_flags, 1, &buf_ptr[curr_loc]))) {
    return -1;
  }

  curr_loc++;
  uint32_t stream_id = 0;
  if (bpf_probe_read(&stream_id, 4, &buf_ptr[curr_loc])) {
    return -1;
  }

  stream_id = bpf_ntohl(stream_id);
  curr_loc += 4;

  switch (frame_type) {
    // Data Frame
    case H2_DATA:
      break;

    // Reset Stream
    case H2_RST_STREAM: {
      uint32_t error = 0;
      success = bpf_probe_read(&error, 4, &buf_ptr[curr_loc]);
      if (unlikely(success < 0)) {
        return success;
      }
      send_h2_reset(ctx, event, stream_id, error);
      break;
    }
    // Settings_frame
    case H2_SETTINGS: {
      char *settings = (char *)event->event_info;

      event->mdata.length = frame_length;
      size_t length = frame_length;
      if (length <= 0) {
        return -1;
      }
      size_t length_minus_1 = length - 1;
      asm volatile("" : "+r"(length_minus_1) :);
      length = length_minus_1 + 1;

      if (length_minus_1 < EC_MAX_EVENT_DATA_SIZE) {
        bpf_probe_read(settings, (uint32_t)length, &buf_ptr[curr_loc]);
        event->mdata.event_type = EC_H2_EVENT_SETTINGS;
        uint64_t data_length = frame_length + sizeof(ec_ebpf_event_metadata_t);
        if (data_length > sizeof(ec_ebpf_events_t)) {
          data_length = sizeof(ec_ebpf_events_t);
        }
        bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU, event,
                              data_length);
      }
      break;
    }
    // Ping frame
    case H2_PING:
      // Currently not distinguishing incoming and outgoing pings
      send_h2_ping(NULL, event, NULL);
      break;

    // GO_AWAY
    case H2_GOAWAY: {
      ec_h2_go_away_t *data = (ec_h2_go_away_t *)event->event_info;
      if (unlikely(
              bpf_probe_read(&data->mdata.last_stream_id, 4,
                             &buf_ptr[curr_loc]))) {
        return -1;
      }
      data->mdata.last_stream_id = bpf_ntohl(data->mdata.last_stream_id);
      if (unlikely(bpf_probe_read(&data->mdata.error_code, 4,
                                  &buf_ptr[curr_loc]))) {
        return -1;
      }
      curr_loc +=8;
      event->mdata.event_type = EC_H2_EVENT_GO_AWAY;
      event->mdata.length = sizeof(ec_h2_go_away_mdata_t);

      bpf_perf_event_output(
          ctx, &h2_events, BPF_F_CURRENT_CPU, event,
          sizeof(ec_ebpf_event_metadata_t) + sizeof(ec_h2_go_away_mdata_t));
      break;

      size_t length = frame_length - curr_loc;

      uint8_t * debug_data = (uint8_t *)data->debug_data;
      if (length > EC_MAX_GO_AWAY_DATA_SIZE){
        length = EC_MAX_GO_AWAY_DATA_SIZE;
      }
      success = bpf_probe_read(debug_data, (uint32_t) length,
                               &buf_ptr[curr_loc]);
      if (unlikely(success < 0)) {
        event->mdata.length = sizeof(ec_h2_go_away_mdata_t);
        bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU, event,
                            sizeof(ec_ebpf_event_metadata_t) +
                            sizeof(ec_h2_go_away_mdata_t));
        return 0;
      }
      event->mdata.length = length + sizeof(ec_h2_go_away_mdata_t);
      uint64_t data_length = length + sizeof(ec_ebpf_event_metadata_t)
                            + sizeof(ec_h2_go_away_mdata_t);
      if (unlikely(data_length > sizeof(ec_ebpf_events_t))){
        data_length = sizeof(ec_ebpf_events_t);
      }
      bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU,
                            event, data_length);
      break;
    }
    // Header Frame
    case H2_HEADERS: {
      if (unlikely(client)) {
        send_h2_headers(ctx, event, stream_id);
      }
      break;
    }
    default:
      break;
  }

  if ((frame_flags & H2_END_STREAM) != 0){
    send_h2_end(ctx, event, stream_id);
  }

  return frame_length + FRAME_HEADER_SIZE;
}

#endif
