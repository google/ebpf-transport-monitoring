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

#ifndef _SOURCES_COMMON_DEFINES_H_
#define _SOURCES_COMMON_DEFINES_H_

#ifdef CORE
#include "vmlinux.h"  // NOLINT(build/include)
#endif

#define TRUE 1
#define FALSE 0

#define VERSION 1

#define FRAME_HEADER_SIZE 9

// TLS frame has a header of size 5 before the data starts.
#define TLS_DATA_OFFSET  5
// We are assuming that 8 bytes of data will be enough to differentiate
// between all the connections using openssl, this assumption is baed on the
// huge number of possibilities that 8 byte data provides.
#define TLS_DATA_HASH_SIZE  8
#define TLS_TOTAL_DATA_SIZE (TLS_DATA_OFFSET + TLS_DATA_HASH_SIZE)

// The TLS frame type 23 carries data which we will use for correlation
// purposes. Handshake data can have the same data and hence cannot be
// used as a hash.
#define TLS_APPLLICATION_DATA_TYPE 23
/*
 Maximum PIDs that can be tracked at once.
 The more PIDs being traced at once the higher the probability that events
 will be missed by the user space process. In case more applications need
 to be traced start another instance of this tracer.

 That being said the number 16 is arbitrary and may be increased or
 decreased based on deployment feedback. Some events can be missed, hence factor
 in the use of multiple ring buffers and threads and priority of events while
 changing this value. */
#define MAX_PID_TRACED 16

/*
Maximum connections traced. The value is an arbitrary limit.
*/
#define MAX_CONN_TRACED MAX_PID_TRACED * 16

/* In theory this count is 2^32 - 1
  In practice the number of concurrent streams per connection is 100.
  However, averaging across all connections the value must be much lower than
  100
*/
#define MAX_AVG_CONCURRENT_STREAMS 10

#define MAX_TCP_CONN_TRACED MAX_CONN_TRACED
#define MAX_H2_CONN_TRACED MAX_CONN_TRACED

#define MAX_H2_STREAMS MAX_H2_CONN_TRACED* MAX_AVG_CONCURRENT_STREAMS

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#endif  // _SOURCES_COMMON_DEFINES_H_
