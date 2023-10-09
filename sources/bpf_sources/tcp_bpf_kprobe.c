#ifdef CORE
  #include "vmlinux.h"
  #include "missing_defs.h"
  #include "struct_flavors.h"
#else
  #define KBUILD_MODNAME "lightfoot"
  #include <linux/bpf.h>
  #include <linux/types.h>
  #include <linux/socket.h>
  #include <linux/net.h>
  #include <linux/tcp.h>
  #include <linux/version.h>
  #include <net/inet_sock.h>
#endif

#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"

#include "bpf/bpf_endian.h"
#include "correlator_types.h"
#include "defines.h"
#include "events.h"

#ifdef CORE
extern u32 LINUX_KERNEL_VERSION __kconfig;
#endif

#ifndef CORE
  #define KERN_READ(dst, sz, src)   bpf_probe_read(dst, sz, src)
#else
  #define KERN_READ(dst, sz, src)   bpf_core_read(dst, sz, src)
#endif

// 2 second
#define SAMPLE_TIME   2000000000
static __always_inline uint32_t get_curr_pid(void* map) {
  if (map == NULL) {
    return 0;
  }
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t ppid = (id >> 32);
  uint8_t* trace_pid = bpf_map_lookup_elem(map, &ppid);
  if (trace_pid == NULL) {
    return 0;
  }
  return ppid;
}


/* tcp_events is the buffer that is used to communicate events with userspace.
For definition of different events please refer to events.h */
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} tcp_events SEC(".maps");

/* tcp_pid_filter is a map of pids that the probe is supposed to trace */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u8));
  __uint(max_entries, MAX_PID_TRACED);
} tcp_pid_filter SEC(".maps");

/* tcp_connection is a map of connections.
All the probes used have struct sock * as an argument in the raw tracepoint.
We will use that as key. Value is the last sampled timestamp.
The timestamp value will be used in case of sampling congestion values.*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_connection SEC(".maps");

/* tcp_retransmits is a map of connections.
Retransmits corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_retransmits SEC(".maps");

/* Because of limited stack space in eBPF we usually store variables on heap
using maps. The BPF_MAP_TYPE_PERCPU_ARRAY avoids contention and need for locks
since the code will always run inline to the process thread.*/
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(ec_ebpf_events_t));
  __uint(max_entries, 1);
} event_heap SEC(".maps");

/* tcp_rtt is a map of connections.
Retransmits corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_rtt SEC(".maps");

/* tcp_snd_bytes is a map of connections.
Retransmits corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_snd_bytes SEC(".maps");

/* tcp_rcv_bytes is a map of connections.
Retransmits corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_rcv_bytes SEC(".maps");

/* tcp_snd_cwnd is a map of connections.
Retransmits corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_snd_cwnd SEC(".maps");

/* tcp_rcv_cwnd is a map of connections.
Receive window corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_rcv_cwnd SEC(".maps");

static __always_inline ec_ebpf_events_t * get_event(uint32_t pid){
  const int kZero = 0;
  ec_ebpf_events_t * event = bpf_map_lookup_elem(&event_heap, &kZero);
  if (event == NULL){
    return event;
  }
  event->mdata.sent_recv = 0;
  event->mdata.event_category = EC_CAT_TCP;
  event->mdata.pid = pid;
  event->mdata.timestamp = bpf_ktime_get_ns();
  return event;
}

static __always_inline void send_tcp_start(void * ctx,
                                ec_ebpf_events_t * event,
                                const struct sock * sk){
  uint64_t kZero = 0;
  const struct inet_sock *inet = inet_sk(sk);
  bpf_map_update_elem(&tcp_connection, &sk, &kZero, BPF_NOEXIST);
  event->mdata.event_type = EC_TCP_EVENT_START;
  ec_tcp_start_t * start = (ec_tcp_start_t*)event->event_info;
  KERN_READ(&start->family, sizeof(uint16_t), &sk->__sk_common.skc_family);
  KERN_READ(&start->sport, sizeof(uint16_t), &inet->inet_sport);
  KERN_READ(&start->dport, sizeof(uint16_t), &sk->__sk_common.skc_dport);
  start->dport = bpf_ntohs(start->dport);
  start->sport = bpf_ntohs(start->sport);
  if (start->family == AF_INET) {
    uint32_t* addr = &start->daddr.s_addr;
    KERN_READ(addr, sizeof(uint32_t), &sk->__sk_common.skc_daddr);
    addr = &start->saddr.s_addr;
    KERN_READ(addr, sizeof(uint32_t), &sk->__sk_common.skc_rcv_saddr);
  } else if (start->family == AF_INET6) {
    struct in6_addr* addr = &start->daddr6;
    KERN_READ(addr, sizeof(struct in6_addr), &sk->__sk_common.skc_v6_daddr);
    addr = &start->saddr6;
    KERN_READ(addr, sizeof(struct in6_addr), &sk->__sk_common.skc_v6_rcv_saddr);
  }
  event->mdata.length = sizeof(ec_tcp_start_t);
  bpf_perf_event_output(ctx, &tcp_events, BPF_F_CURRENT_CPU, event,
                        sizeof(ec_ebpf_event_metadata_t) + event->mdata.length);
}

#define READ_TCP_METRIC_TO_MAP(map, metric)   \
  KERN_READ(&metric_value, sizeof(uint32_t), metric); \
  format = bpf_map_lookup_elem(map, &sk); \
  if (format == NULL){ \
    metric_format_t data = {.timestamp = timestamp, .data = metric_value}; \
    bpf_map_update_elem(map, &sk, &data, BPF_ANY); \
  } else { \
    format->timestamp = timestamp; \
    format->data = metric_value; \
  }

static __always_inline int handle_tcp(void * ctx, uint32_t pid,
                                      const struct sock * const sk) {
  uint64_t * value = bpf_map_lookup_elem(&tcp_connection, &sk);
  uint64_t timestamp = bpf_ktime_get_ns();
  if (value != NULL && ((timestamp - *value) < SAMPLE_TIME)) {
    return 0;
  }

  ec_ebpf_events_t * event = get_event(pid);
  if (event == NULL){
    return -1;
  }
  event->mdata.connection_id = (uint64_t) sk;
  if (value == NULL){
    send_tcp_start(ctx, event, sk);
  } else {
    *value = timestamp;
  }

  struct tcp_sock *tcpi = tcp_sk(sk);


  uint32_t metric_value;
  metric_format_t * format;

  READ_TCP_METRIC_TO_MAP(&tcp_rtt, &tcpi->srtt_us);
  READ_TCP_METRIC_TO_MAP(&tcp_snd_cwnd, &tcpi->snd_cwnd);
  READ_TCP_METRIC_TO_MAP(&tcp_rcv_cwnd, &tcpi->rcv_wnd);
  READ_TCP_METRIC_TO_MAP(&tcp_rcv_bytes, &tcpi->bytes_received);
  READ_TCP_METRIC_TO_MAP(&tcp_snd_bytes, &tcpi->bytes_acked);

  uint32_t retrans;
  KERN_READ(&retrans, sizeof(uint32_t), &tcpi->total_retrans);
  uint32_t * retrans_map =
      (uint32_t*) bpf_map_lookup_elem(&tcp_retransmits, &sk);
  if (retrans_map == NULL && retrans > 0) {
    bpf_map_update_elem(&tcp_retransmits, &sk, &retrans, BPF_ANY);
  } else if ((retrans_map != NULL) && ((*retrans_map) != retrans)) {
    *retrans_map = retrans;
  }
  return 0;
}

// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int probe_tcp_sendmsg(struct pt_regs* ctx) {
  uint32_t pid = get_curr_pid(&tcp_pid_filter);
  if (pid == 0){
    return 0;
  }
  const struct sock * sk = (struct sock *) PT_REGS_PARM1(ctx);
  return handle_tcp(ctx, pid, sk);
}

SEC("kprobe/tcp_set_state")
int probe_tcp_set_state(struct pt_regs *ctx)
{
  const struct sock * sk = (const struct sock *)PT_REGS_PARM1(ctx);
  uint64_t * value = bpf_map_lookup_elem(&tcp_connection, &sk);
  if (value == NULL){
    return 0;
  }
  uint32_t pid = get_curr_pid(&tcp_pid_filter);
  if (pid == 0){
    return 0;
  }


  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }

  event->mdata.connection_id = (uint64_t) sk;
  uint32_t old_state;
  KERN_READ(&old_state, sizeof(uint32_t),
            (const void*)&sk->__sk_common.skc_state);

  ec_tcp_state_change_t * ev = (ec_tcp_state_change_t*)event->event_info;
  event->mdata.event_type = EC_TCP_EVENT_STATE_CHANGE;
  ev->old_state = old_state;
  ev->new_state = (uint32_t) PT_REGS_PARM2(ctx);
  event->mdata.length = sizeof(ec_tcp_state_change_t);
  bpf_perf_event_output(ctx, &tcp_events, BPF_F_CURRENT_CPU, event,
                        sizeof(ec_ebpf_event_metadata_t) + event->mdata.length);
  return 0;
}
char LICENSE[] SEC("license") = "GPL";
