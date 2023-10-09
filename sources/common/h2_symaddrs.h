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

#ifndef _SOURCES_COMMON_H2_SYMADDRS_H_
#define _SOURCES_COMMON_H2_SYMADDRS_H_

#ifdef __cplusplus
#include "ebpf_monitor/utils/sym_addrs.h"
#else
#include "sym_addrs.h"  // NOLINT(build/include)
#endif

typedef struct grpc_http2_loc__ {
  sym_location_t connection;
  sym_location_t frame;
  sym_location_t buf_writer;
  sym_location_t write_buffer_len;
  sym_location_t write_buffer_ptr;
} grpc_http2_loc_t;

typedef struct frame_offsets__ {
  member_var_t frameheader_type;
  member_var_t frameheader_flags;
  member_var_t frameheader_length;
  member_var_t frameheader_streamid;
  member_var_t dataframe_data;
  member_var_t rstframe_error;
  member_var_t goawayframe_error;
  member_var_t goawayframe_stream;
  member_var_t goawayframe_data;
  member_var_t settingsframe_data;
  member_var_t client_framer;
  member_var_t server_framer;
  member_var_t framer_bufwriter;
  member_var_t client_laddr;
  member_var_t client_raddr;
  member_var_t server_laddr;
  member_var_t server_raddr;
  member_var_t tcp_ip;
  member_var_t tcp_port;
} grpc_frame_offsets_t;

typedef struct grpc_symbol_types__ {
  int64_t tcp_addr;
} grpc_symbol_types_t;

typedef struct h2_cfg__ {
  grpc_http2_loc_t variables;
  grpc_frame_offsets_t offset;
  grpc_symbol_types_t types;
} h2_cfg_t;

typedef enum {
  /**
   * The DATA frame.
   */
  H2_DATA = 0,
  /**
   * The HEADERS frame.
   */
  H2_HEADERS = 0x01,
  /**
   * The PRIORITY frame.
   */
  H2_PRIORITY = 0x02,
  /**
   * The RST_STREAM frame.
   */
  H2_RST_STREAM = 0x03,
  /**
   * The SETTINGS frame.
   */
  H2_SETTINGS = 0x04,
  /**
   * The PUSH_PROMISE frame.
   */
  H2_PUSH_PROMISE = 0x05,
  /**
   * The PING frame.
   */
  H2_PING = 0x06,
  /**
   * The GOAWAY frame.
   */
  H2_GOAWAY = 0x07,
  /**
   * The WINDOW_UPDATE frame.
   */
  H2_WINDOW_UPDATE = 0x08,
  /**
   * The CONTINUATION frame.  This frame type won't be passed to any
   * callbacks because the library processes this frame type and its
   * preceding HEADERS/PUSH_PROMISE as a single frame.
   */
  H2_CONTINUATION = 0x09,
  /**
   * The ALTSVC frame, which is defined in `RFC 7383
   * <https://tools.ietf.org/html/rfc7838#section-4>`_.
   */
  H2_ALTSVC = 0x0a,
  /**
   * The ORIGIN frame, which is defined by `RFC 8336
   * <https://tools.ietf.org/html/rfc8336>`_.
   */
  H2_ORIGIN = 0x0c
} frame_type;

#define H2_END_STREAM 0x01
#endif  // _SOURCES_COMMON_H2_SYMADDRS_H_
