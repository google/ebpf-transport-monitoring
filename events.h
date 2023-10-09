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

#ifndef _EVENTS_H_
#define _EVENTS_H_

// This is done to make sure headers are self contained.
#ifdef __cplusplus
#include <linux/types.h>
#include <netinet/in.h>
#include <stdint.h>
#else
#ifdef CORE
#include "vmlinux.h"  // NOLINT(build/include)
#else
#include <linux/bpf.h>
#endif
#endif
// The namespace is ebpf_comm.
/* Hence in c type namespace, ec is used as a prefix.
  The largest data block is an array of h2 settings currently,
  which goes to around 240 bytes. With buffer 512 is selected.
*/
#define EC_MAX_EVENT_DATA_SIZE    512


/* The information collected by eBPF will be stored or sent in the form of the
  following packed C struct.*/
typedef struct {
  /* If event is regarding a frame, packet sent from the machine this bit is
  reset. If the packet or frame is received this bit is set. */
  __u32 sent_recv : 1;
  /* Category of the event as defined in ec_event_cat_t */
  __u32 event_category : 4;
  /* Type of event of the above defined category
  eg. ec_tcp_event_t for EC_CAT_TCP */
  __u32 event_type : 7;
  /*Reserved*/
  __u32 reserved : 4;
  /* Length of the event specific data*/
  __u32 length : 16;
  /* PID of the process from which this event originated. */
  __u32 pid;
  /* Timestamp in ns from CLOCK_MONOTONIC source. CLOCK_REALTIME does not allow
  absolute ordering of events. However, this means care must be taken care in
  case of reboots.*/
  __u64 timestamp;
  /*This value is just the value pointer of the pointer used to house the
  connection information by the application or kernel. Hence, the value will be
  unique amongst active connections but not unique over the lifetime of the
  application. The start event must be used to create a globally unique id in
  userspace.*/
  __u64 connection_id;
} ec_ebpf_event_metadata_t;

typedef struct {
  ec_ebpf_event_metadata_t mdata;
  /* Event specific data as defined by the event*/
  __u8 event_info[EC_MAX_EVENT_DATA_SIZE];
} ec_ebpf_events_t;

/* Event categories. */
typedef enum {
  EC_CAT_TCP,
  EC_CAT_HTTP2,
  EC_CAT_TLS,
  EC_CAT_MAX
} ec_event_cat_t;

#if EC_CAT_MAX > 15
#error "Category is defined to have only 4 bits"
#endif

typedef enum {
  /* This type defines a start of the connection.
  ec_tcp_start_t will be used as the event specific information.*/
  EC_TCP_EVENT_START,
  /* In case of state change where states are described in
  "include/net/tcp_states.h". ec_tcp_state_change_t will be sent as event
  specific information.*/
  EC_TCP_EVENT_STATE_CHANGE,
  /* A Packet is retransmitted. __u32 value corresponding to number of
  retransmitted packets for the duration of entire connection.*/
  EC_TCP_EVENT_RETRANS,
  /* TCP congestion control related information. ec_tcp_congestion_t
  will be used as the event specific information. */
  EC_TCP_EVENT_CONGESTION,
  /* Packet dropped in kernel. No event specific information. */
  EC_TCP_EVENT_PACKET_DROP,
  /* Connection reset. No event specific information. */
  EC_TCP_EVENT_RESET,
  EC_TCP_EVENT_MAX
} ec_tcp_event_t;

typedef struct {
  __u32 old_state;
  __u32 new_state;
} ec_tcp_state_change_t;

/* The values are in network byte order */
typedef struct {
  __u8 family;  // IPv4 or IPv6.
  __u16 dport;
  __u16 sport;
  __u16 protocol;
  union {
    struct in_addr daddr;
    struct in6_addr daddr6;
  };
  union {
    struct in_addr saddr;
    struct in6_addr saddr6;
  };
} ec_tcp_start_t;

typedef struct {
  __u32 snd_cwnd;        // Sender congestion window in packets.
  __u32 rcv_cwnd;        // Seceive congestion window in bytes.
  __u32 srtt;            // Smooth Round trip time.
  __u32 snd_wnd;         // Received flow control window.
  __u32 bytes_received;  // Received bytes.
  __u32 bytes_sent;      // Sent bytes.
} ec_tcp_congestion_t;

typedef enum {
  /*This is the first time this connection is seen. */
  EC_H2_EVENT_START,
  /* Stream state as defined in ec_h2_stream_state_t and stream id will be
  captured */
  EC_H2_EVENT_STREAM_STATE,
  /* An array of h2 settings as defined in ec_h2_setting_t are captured. */
  EC_H2_EVENT_SETTINGS,
  /* In case the window update is for the connection then a __u32 value
  corresponding to the update will be provided. This value is not the absolute
  window but the delta of window update */
  EC_H2_EVENT_WINDOW_UPDATE,
  /* Go away message as defined in ec_h2_go_away is captured.*/
  EC_H2_EVENT_GO_AWAY,
  /* Connection closed*/
  EC_H2_EVENT_CLOSE,
} ec_h2_event_t;

typedef enum {
  EC_H2_STREAM_BEGIN,
  EC_H2_STREAM_END,
  EC_H2_STREAM_WINDOW_UPDATE,
  EC_H2_STREAM_RESET,
  EC_H2_STREAM_UNKNOWN,
  EC_H2_STREAM_MAX
} ec_h2_stream_state_t;

typedef struct {
  __u32 stream_id;
  ec_h2_stream_state_t state;
  __u32 value;
} ec_h2_state_t;

typedef struct {
  __u32 last_stream_id;  // Last stream that will be accepted by the server.
  __u32 error_code;      // Error code sent by the server.
} ec_h2_go_away_mdata_t;

#define EC_MAX_GO_AWAY_DATA_SIZE  \
      EC_MAX_EVENT_DATA_SIZE - sizeof (ec_h2_go_away_mdata_t)

typedef struct {
  ec_h2_go_away_mdata_t mdata;
  uint8_t debug_data [EC_MAX_GO_AWAY_DATA_SIZE];
} ec_h2_go_away_t;

typedef enum {
  /* A __u32 with the state corresponding to ec_tls_state_t is captured. */
  EC_TLS_EVENT_STATE,
  EC_TLS_EVENT_MAX
} ec_tls_event_t;

typedef enum {
  EC_TLS_STATE_ERROR,
  EC_TLS_STATE_ESTABLISED,
  EC_TLS_MAX
} ec_tls_state_t;

typedef struct _metric_format_t {
  __u64 timestamp;
  __u64 data;
} metric_format_t;

#endif  // _EVENTS_H_
