#ifndef SOURCES_BPF_SOURCES_H_
#define SOURCES_BPF_SOURCES_H_

#ifdef CORE
#include "vmlinux.h"
#else
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/types.h>
#endif

#include "bpf/bpf_tracing.h"
#include "defines.h"
#include "events.h"

/* These maps are supposed to be shared by all programs. Hence it is defined 
in a .h file to simply declaration in the bpf program files.*/

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} h2_events SEC(".maps");

/* h2_connection is a map of connections. The value is bumped every
time a frame is received to make sure the active connections are stored. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, MAX_H2_CONN_TRACED);
} h2_connection SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_H2_CONN_TRACED);
} h2_ping_counter SEC(".maps");

/* Map keep track of active streams for all connections */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, MAX_H2_STREAMS);
} h2_stream_id SEC(".maps");

/* Map keeps count of absolute number of streams per connection */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_H2_CONN_TRACED);
} h2_stream_count SEC(".maps");

/* Map keeps count of streams resets per connection */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_H2_CONN_TRACED);
} h2_reset_stream_count SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(ec_ebpf_events_t));
  __uint(max_entries, 1);
} h2_event_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} openssl_correlation_events SEC(".maps");

/* This map keeps track of which connections we don't need to collect
 correlation information from anymore.*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(uint8_t));
  __uint(max_entries, MAX_H2_CONN_TRACED * 2);
} data_sample_cntl SEC(".maps");


#endif
