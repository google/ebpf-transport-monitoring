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
#include "defines.h"
#include "correlator_types.h"
#include "maps.h"
#include "events.h"

// The number of blocks in msghdr can be arbitrarily long
// This limit was defined to support older kernels with a small instruction
// count, but we are keeping it the same for now.
#define LOOP_LIMIT  32

#ifdef CORE
extern u32 LINUX_KERNEL_VERSION __kconfig;
#endif

#ifndef CORE
  #define KERN_READ(dst, sz, src)   bpf_probe_read_kernel(dst, sz, src)
#else
  #define KERN_READ(dst, sz, src)   bpf_core_read(dst, sz, src)
#endif

// 2 second
#define SAMPLE_TIME   2000000000

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
The timestamp value will be used in case of sampling congestion values.

Raw tracepoints don't get the context of the program hence the PID value must
be saved in kProbe.
*/

struct tcp_conn_t {
  uint64_t timestamp;
  uint64_t pid;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(struct tcp_conn_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_connection SEC(".maps");

/* tcp_events is the buffer that is used to communicate events with userspace.
For definition of different events please refer to events.h */
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} tcp_events SEC(".maps");

/* tcp_retransmits is a map of connections.
Retransmits corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_retransmits SEC(".maps");

/* tcp_rtt is a map of connections.
Round trip latency corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_rtt SEC(".maps");

/* tcp_snd_bytes is a map of connections.
No. of bytes acked corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_snd_bytes SEC(".maps");

/* tcp_rcv_bytes is a map of connections.
Num of bytes read corresponding to tcp connections.
*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(metric_format_t));
  __uint(max_entries, MAX_TCP_CONN_TRACED);
} tcp_rcv_bytes SEC(".maps");

/* tcp_snd_cwnd is a map of connections.
Send window size corresponding to tcp connections.
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

/* Because of limited stack space in eBPF we usually store variables on heap
using maps. The BPF_MAP_TYPE_PERCPU_ARRAY avoids contention and need for locks
since the code will always run inline to the process thread.*/
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(ec_ebpf_events_t));
  __uint(max_entries, 1);
} event_heap SEC(".maps");

static __always_inline uint32_t get_curr_pid() {
  uint32_t ppid = (bpf_get_current_pid_tgid() >> 32);
  uint8_t* trace_pid = bpf_map_lookup_elem(&tcp_pid_filter, &ppid);
  if (trace_pid == NULL) {
    return 0;
  }
  return ppid;
}

static __always_inline ec_ebpf_events_t * get_event(uint32_t pid){
  const int kZero = 0;
  ec_ebpf_events_t * event = bpf_map_lookup_elem(&event_heap, &kZero);
  if (unlikely(event == NULL)){
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
  metric_format_t format = {.data = 0, .timestamp = event->mdata.timestamp};
  bpf_map_update_elem(&tcp_retransmits, &sk,
                      &format, BPF_ANY);
  const struct inet_sock *inet = inet_sk(sk);
  struct tcp_conn_t conn_info = {.timestamp = 0, .pid = event->mdata.pid};
  bpf_map_update_elem(&tcp_connection, &sk, &conn_info, BPF_NOEXIST);
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

/*
We are using raw tracepoint because it gives the lowest overhead.

TP_PROTO(const struct sock *sk, const int oldstate, const int newstate),
*/
SEC("raw_tracepoint/inet_sock_set_state")
int sock_state(struct bpf_raw_tracepoint_args *ctx)
{
  uint16_t protocol;
  const struct sock * sk = (const struct sock *)ctx->args[0];
  const struct tcp_conn_t * value = bpf_map_lookup_elem(&tcp_connection, &sk);
  if (value == NULL){
    return 0;
  }
  uint32_t pid = value->pid;
  if ((uint32_t) ctx->args[2] == TCP_CLOSE){
    bpf_map_delete_elem(&tcp_connection, &sk);
  }
  #ifndef CORE
  #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
    uint8_t proto;
    KERN_READ(&proto, 1, (uint8_t*)(((void *) &(sk->sk_gso_max_segs)) - 3));
    protocol = proto;
  #else
    KERN_READ(&protocol, sizeof(uint16_t), &(sk->sk_protocol));
  #endif
  #else
  if (bpf_core_field_exists(struct sock___old, __sk_flags_offset)) {
    uint8_t proto;
    KERN_READ(&proto, 1, (uint8_t*)(((void *) &(sk->sk_gso_max_segs)) - 3));
    protocol = proto;
  } else {
    KERN_READ(&protocol, sizeof(uint16_t), &(sk->sk_protocol));
  }
  #endif

  if (likely(protocol != IPPROTO_TCP)){
    return 0;
  }

  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }
  event->mdata.connection_id = (uint64_t) sk;

  ec_tcp_state_change_t * ev = (ec_tcp_state_change_t*)event->event_info;
  event->mdata.event_type = EC_TCP_EVENT_STATE_CHANGE;
  ev->old_state = (uint32_t) ctx->args[1];
  ev->new_state = (uint32_t) ctx->args[2];
  event->mdata.length = sizeof(ec_tcp_state_change_t);
  bpf_perf_event_output(ctx, &tcp_events, BPF_F_CURRENT_CPU, event,
                        sizeof(ec_ebpf_event_metadata_t) + event->mdata.length);
  return 0;
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
  struct tcp_conn_t * value = bpf_map_lookup_elem(&tcp_connection, &sk);
  uint64_t timestamp = bpf_ktime_get_ns();
  if (value != NULL && ((timestamp - value->timestamp) < SAMPLE_TIME)) {
    return 0;
  }

  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }
  event->mdata.connection_id = (uint64_t) sk;
  if (value == NULL){
    send_tcp_start(ctx, event, sk);
  } else {
    value->timestamp = timestamp;
  }

  struct tcp_sock *tcpi = tcp_sk(sk);

  uint32_t metric_value;
  metric_format_t * format;

  KERN_READ(&metric_value, sizeof(uint32_t), &tcpi->srtt_us);
  format = bpf_map_lookup_elem(&tcp_rtt, &sk);
  if (format == NULL){
    metric_format_t data = {.timestamp = timestamp, .data = metric_value >> 3};
    bpf_map_update_elem(&tcp_rtt, &sk, &data, BPF_ANY);
  } else {
    format->timestamp = timestamp;
    format->data = metric_value >> 3;
  }

  READ_TCP_METRIC_TO_MAP(&tcp_snd_cwnd, &tcpi->snd_cwnd);
  READ_TCP_METRIC_TO_MAP(&tcp_rcv_cwnd, &tcpi->rcv_wnd);
  READ_TCP_METRIC_TO_MAP(&tcp_rcv_bytes, &tcpi->bytes_received);
  READ_TCP_METRIC_TO_MAP(&tcp_snd_bytes, &tcpi->bytes_acked);
  return 0;
}


static inline const struct iovec *iter_iov(const struct iov_iter *iter)
{

	if (iter->iter_type == ITER_UBUF)
		return (struct iovec *) &(iter->__ubuf_iovec);
	return iter->__iov;
}

static __always_inline int get_tls_hash(void * ctx, const struct sock * sk,
                                        struct msghdr * msghdr) {
  struct iov_iter iter;
  KERN_READ(&iter,sizeof(struct iov_iter),&(msghdr->msg_iter));

  const struct iovec* iov;
  if (bpf_core_field_exists(struct iov_iter___old, iov)) {
    KERN_READ(&iov,sizeof(struct iovec*), 
              (((const struct iov_iter___old*) &(iter))->iov));
  } else {
    iov = iter_iov(&iter);
  }

  size_t segs;
  KERN_READ(&segs, sizeof(segs), &iter.nr_segs);

  struct iovec iov_cpy;
  uint8_t byte = 0 ;
  int i;

  // Go through the buffers to find the start of a tls data frame.
  for (i = 0; i < LOOP_LIMIT && i < segs; ++i) {
    KERN_READ(&iov_cpy, sizeof(struct iovec), &iov[i]);
    if (iov_cpy.iov_len == 0)
      continue;
    bpf_probe_read_user(&byte, sizeof(byte), iov_cpy.iov_base);
    if (byte == 23){
      break;
    }
  }

  // If a TLS data frame is found try to read a data hash.
  if(i != LOOP_LIMIT){
    // Don't read anything if there are less than 8 bytes in the data.
    if (iov_cpy.iov_len < TLS_TOTAL_DATA_SIZE) {
      return 0;
    }
    const int kZero = 0;
    openssl_correlation * info = (openssl_correlation * )
          bpf_map_lookup_elem(&event_heap, &kZero);
    if (info == NULL){
      return 0;
    }
    info->mdata.type = kSslCorrelationInfo;
    info->mdata.conn_id = (uint64_t) sk;
    data_sample_t* sample = (data_sample_t*) info->info;
    sample->level = TCP_LEVEL;
    char *data_base = iov_cpy.iov_base;
    if (bpf_probe_read_user(&sample->data, TLS_DATA_HASH_SIZE,
                  &data_base[TLS_DATA_OFFSET])){
      return 0;
    }
    bpf_perf_event_output(ctx, &openssl_correlation_events, BPF_F_CURRENT_CPU,
                          info, sizeof(openssl_correlation));
  }
  return 0;
}

/*
This function is called on a per packet basis and hence should be
sampled.
TP_PROTO(struct sock *sk, struct sk_buff *skb),
*/
SEC("raw_tracepoint/tcp_probe")
int tcp_congestion(struct bpf_raw_tracepoint_args *ctx)
{
  const struct sock * sk = (const struct sock *)ctx->args[0];
  const struct tcp_conn_t * value = bpf_map_lookup_elem(&tcp_connection, &sk);
  if (value == NULL){
    return 0;
  }
  return handle_tcp(ctx, value->pid, sk);
}

// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int probe_tcp_sendmsg(struct pt_regs* ctx) {
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }
  const struct sock * sk = (struct sock *) PT_REGS_PARM1(ctx);
  handle_tcp(ctx, pid, sk);

  uint8_t *cntl = bpf_map_lookup_elem(&data_sample_cntl, &sk);
  if (cntl != NULL)  {
    struct msghdr * msghdr = (struct msghdr *) PT_REGS_PARM2(ctx);
    get_tls_hash(ctx, sk, msghdr);
  }
  return 0;
}

/*
Retransmission event
 
For tcp_retransmit_skb,
TP_PROTO(struct sock *sk, struct sk_buff *skb)

tcp_retransmit_synack will not be traced.
This event will not be sent via perf buffer because, in case of a lot of
retransmits these events will fill up the queue can cause other events to be
missed similar to a DOS. The data will be stored in a map, which userspace will
sample.
*/
SEC("raw_tracepoint/tcp_retransmit_skb")
int tcp_retransmit(struct bpf_raw_tracepoint_args *ctx)
{
  const struct sock * sk = (const struct sock *)ctx->args[0];

  uint64_t * value = bpf_map_lookup_elem(&tcp_connection, &sk);
  if (value == NULL){
    return 0;
  }

  struct tcp_sock *tcpi = tcp_sk(sk);
  uint32_t retransmit;
  KERN_READ(&retransmit, sizeof(uint32_t), &tcpi->total_retrans);
  metric_format_t format = {.timestamp =  bpf_ktime_get_ns(),
                            .data = retransmit};
  metric_format_t * retrans_value = bpf_map_lookup_elem(&tcp_retransmits, &sk);
  if (retrans_value == NULL){
    bpf_map_update_elem(&tcp_retransmits, &sk, &format, BPF_ANY);
  } else {
    *retrans_value = format;
  }

  return 0;
}

static __always_inline int tcp_reset_event(struct bpf_raw_tracepoint_args *ctx,
                                    int send_recv){
  const struct sock * sk = (const struct sock *)ctx->args[0];
  struct tcp_conn_t * value = bpf_map_lookup_elem(&tcp_connection, &sk);
  if (value == NULL){
    return 0;
  }
  ec_ebpf_events_t * event = get_event(value->pid);
  if (unlikely(event == NULL)){
    return -1;
  }

  event->mdata.connection_id = (uint64_t) sk;
  event->mdata.event_type = EC_TCP_EVENT_RESET;
  event->mdata.sent_recv = send_recv;
  event->mdata.length = 0;
  bpf_perf_event_output(ctx, &tcp_events, BPF_F_CURRENT_CPU, event,
                        sizeof(ec_ebpf_event_metadata_t));
  return 0;
}
/*
tcp_send_reset
TP_PROTO(struct sock *sk, struct sk_buff *skb),
*/
SEC("raw_tracepoint/tcp_send_reset")
int tcp_send_reset(struct bpf_raw_tracepoint_args *ctx)
{
  return tcp_reset_event(ctx, 0);
}

/*
tcp_receive_reset
TP_PROTO(struct sock *sk, struct sk_buff *skb),
*/
SEC("raw_tracepoint/tcp_receive_reset")
int tcp_receive_reset(struct bpf_raw_tracepoint_args *ctx)
{
  return tcp_reset_event(ctx, 1);
}

char LICENSE[] SEC("license") = "GPL";
