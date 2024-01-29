#ifdef CORE
  #include "vmlinux.h"
#else
  #include <linux/bpf.h>
  #include <linux/types.h>
  #include <linux/in.h>
  #include <linux/in6.h>
#endif

#include "bpf/bpf_endian.h"
#include "bpf/bpf_tracing.h"
#include "defines.h"
#include "events.h"
#include "maps.h"
#include "correlator_types.h"
#include "parse_h2_frame.h"

typedef struct func_args
{
  char * buf;
  uint64_t ptr;
  int len;
}func_args_t;

#define PRISM_LEN 24
#define READ      0
#define WRITE     1

// This is a arbitrary number selected for the number of
// frames that could be there in one Openssl write or READ
#define FRAMES_PER_WRITE    200
/* h2_grpc_pid_filter is a map of pids that the probe is supposed to trace */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u8));
  __uint(max_entries, MAX_PID_TRACED);
} openssl_pid_filter SEC(".maps");

/* openssl_connections stores the connections that are to be traced.
 i.e. if it is a h2 connection*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(__u8));
  __uint(max_entries, MAX_H2_CONN_TRACED);
} openssl_connections SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(func_args_t));
  __uint(max_entries, 16);
} h2_read_args_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(func_args_t));
  __uint(max_entries, 16);
} h2_write_args_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, 64);
  __uint(max_entries, 1);
} buffer_heap SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(int));
  __uint(max_entries, 2 * MAX_H2_CONN_TRACED);  
} data_offset SEC(".maps");

/* connection_bio_map is a map which keeps track of the bio ptr and the 
corresponding ssl_ptr.*/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, MAX_H2_CONN_TRACED);
} connection_bio_map SEC(".maps");


static __always_inline uint64_t get_curr_tgid_pid() {
  uint64_t ppid = bpf_get_current_pid_tgid();
  uint32_t pid = ppid >> 32;
  uint8_t* trace_pid = bpf_map_lookup_elem(&openssl_pid_filter, &pid);
  if (unlikely(trace_pid == NULL)) {
    return 0;
  }
  return ppid;
}

static __always_inline ec_ebpf_events_t * get_event(uint32_t pid){
  const int kZero = 0;
  ec_ebpf_events_t * event = bpf_map_lookup_elem(&h2_event_heap, &kZero);
  if (unlikely(event == NULL)){
    return event;
  }
  event->mdata.event_category = EC_CAT_HTTP2;
  event->mdata.pid = pid;
  event->mdata.timestamp = bpf_ktime_get_ns();
  return event;
}

static __inline uint8_t check_prism (const char * buffer, uint32_t len) {
  int kZero = 0;
  if (len < 10) {
    return 0;
  }
  char * buf = bpf_map_lookup_elem(&buffer_heap, &kZero);
  if (buf == NULL){
    return 0;
  }

  if (bpf_probe_read_user(buf, 10, buffer) < 0){
    return 0;
  }

  if ((buf[0] == 0x50 ) && (buf[1] == 0x52 ) && (buf[2] == 0x49 ) &&
      (buf[3] == 0x20 ) && (buf[4] == 0x2a ) && (buf[5] == 0x20 ) &&
      (buf[6] == 0x48 ) && (buf[7] == 0x54 ) && (buf[8] == 0x54 ) &&
      (buf[9] == 0x50 ) /*&&(buf[10] == 0x2f)
      &&(buf[11] == 0x32 ) && (buf[12] == 0x2e ) &&(buf[13] == 0x30 ) &&
      (buf[14] == 0x0d ) &&(buf[15] == 0x0a ) &&(buf[16] == 0x0d ) &&
      (buf[17] == 0x0a ) &&(buf[18] == 0x53 ) &&(buf[19] == 0x4d ) &&
      (buf[20] == 0x0d ) &&(buf[21] == 0x0a ) &&(buf[22] == 0x0d ) &&
      (buf[23] == 0x0a)*/) {
    return 1;
  }
  return 0;
}

static __always_inline uint32_t process_data(void * ctx, uint32_t pid,
                                             uint8_t rw, uint64_t ssl_ptr,
                                             char * buf, uint32_t data_len ) {
  int curr_loc = 0;

  uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, &ssl_ptr);
  uint8_t trace;
  if (trace_conn == NULL) {
    trace = check_prism(buf, data_len);
    curr_loc += 24;
    bpf_map_update_elem(&openssl_connections, &ssl_ptr, &trace, BPF_NOEXIST);
  } else {
    trace = *trace_conn;
  }
  if (trace == 0){
      return 0;
  }
  if (trace_conn == NULL){
    uint64_t timestamp = bpf_ktime_get_ns();
    metric_format_t format = {.data = 0, .timestamp = timestamp};
    bpf_map_update_elem(&h2_connection, &ssl_ptr,
                        &timestamp, BPF_ANY);
    bpf_map_update_elem(&h2_stream_count, &ssl_ptr,
                        &format, BPF_ANY);
    bpf_map_update_elem(&h2_reset_stream_count, &ssl_ptr,
                        &format, BPF_ANY);
    int kZero = 0;
    openssl_correlation * info = (openssl_correlation * )
        bpf_map_lookup_elem(&buffer_heap, &kZero);
    if (info == NULL){
      return 0;
    }
    info->mdata.type = kSslNewConnection;
    info->mdata.conn_id = ssl_ptr;

    bpf_perf_event_output(ctx, &openssl_correlation_events, BPF_F_CURRENT_CPU,
                          info, sizeof(openssl_mdata_t)); 
  }
  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }
  event->mdata.connection_id = ssl_ptr;
  event->mdata.sent_recv = rw;

  ssl_ptr += rw;
  int * value = bpf_map_lookup_elem(&data_offset, &ssl_ptr);
  if (value != NULL){
    curr_loc += *value;
  }
  ssl_ptr -= rw;

  for (int i = 0; i < FRAMES_PER_WRITE; i ++){
    if (curr_loc >= data_len) {
      // Also have to consider the case where half frame header is received
      // There isn't data enough for another frame
      // Store offset depending on rw
      ssl_ptr += rw;
      curr_loc -= data_len;
      if (value == NULL){
        bpf_map_update_elem(&data_offset, &ssl_ptr, &curr_loc, BPF_NOEXIST);
      } else {
        *value = curr_loc;
      }
      break;
    }
    int size = parse_h2_frame(ctx, &buf[curr_loc],
                              data_len - curr_loc, event, rw);
    if (size < 0){
      return 0;
    }
    curr_loc = curr_loc + size;
  }
  return 0;
}

// Function signature being probed:
// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/openssl_write_probe")
int probe_entry_SSL_write(struct pt_regs* ctx) {
  uint64_t pid = get_curr_tgid_pid();
  if (pid == 0){
    return 0;
  }
  uint64_t ssl_ptr = (uint64_t) PT_REGS_PARM1(ctx);
  func_args_t* args = bpf_map_lookup_elem(&h2_write_args_heap, &pid);
  if (unlikely(args == NULL)) {
    int kZero = 0;
    func_args_t * args = (func_args_t * )
        bpf_map_lookup_elem(&buffer_heap, &kZero);
    if (args == NULL){
      return 0;
    }
    args->ptr = ssl_ptr;
    args->buf = (char*)PT_REGS_PARM2(ctx);
    args->len = (uint32_t)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&h2_write_args_heap, &pid, args, BPF_NOEXIST);
  } else {
    args->ptr = ssl_ptr;
    args->buf = (char*)PT_REGS_PARM2(ctx);
    args->len = (uint32_t)PT_REGS_PARM3(ctx);
  }
  return 0;
}

SEC("uprobe/openssl_write_ret_probe")
int probe_ret_SSL_write(struct pt_regs* ctx) {
  uint64_t pid = get_curr_tgid_pid();
  if (pid == 0){
    return 0;
  }
  func_args_t* args = bpf_map_lookup_elem(&h2_write_args_heap, &pid);
  if (args != NULL) {
    uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, &args->ptr);
    if (trace_conn != NULL && *trace_conn == 0) {
      return 0;
    }
    if (args->buf != NULL) {
      process_data(ctx, pid>>32, WRITE, args->ptr, args->buf, args->len);
    }
  }
  return 0;
}

// Function signature being probed:
// int SSL_read(SSL *s, void *buf, int num)
SEC("uprobe/openssl_read_probe")
int probe_entry_SSL_read(struct pt_regs* ctx) {
  uint64_t pid = get_curr_tgid_pid();
  if (pid == 0){
    return 0;
  }
  uint64_t ssl_ptr = (uint64_t) PT_REGS_PARM1(ctx);
  func_args_t* args = bpf_map_lookup_elem(&h2_read_args_heap, &pid);
  if (unlikely(args == NULL)) {
    int kZero = 0;
    func_args_t * args = (func_args_t * )
        bpf_map_lookup_elem(&buffer_heap, &kZero);
    if (args == NULL){
      return 0;
    }
    args->ptr = ssl_ptr;
    args->buf = (char*)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&h2_read_args_heap, &pid, args, BPF_NOEXIST);
  } else {
    args->ptr = (uint64_t) PT_REGS_PARM1(ctx);
    args->buf = (char*)PT_REGS_PARM2(ctx);
  }
  return 0;
}

SEC("uprobe/openssl_read_ret_probe")
int probe_ret_SSL_read(struct pt_regs* ctx) {
  uint64_t pid = get_curr_tgid_pid();
  if (pid == 0){
    return 0;
  }
  func_args_t* args = bpf_map_lookup_elem(&h2_read_args_heap, &pid);
  if (args != NULL) {
    uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, &args->ptr);
    if (trace_conn != NULL && *trace_conn == 0) {
      return 0;
    }
    args->len = PT_REGS_RC(ctx);
    if (args->len < 0){
      return 0;
    }
    if (args->buf != NULL) {
      process_data(ctx, pid>>32, READ, args->ptr, args->buf, args->len);
    }
  }
  return 0;
}

/*
Currently in our case we place our probe in sendmsg of tcp so we need only
w bio*/
SEC("uprobe/openssl_set_bio")
int probe_entry_SSL_set_bio(struct pt_regs* ctx) {
  uint64_t pid = get_curr_tgid_pid();
  if (pid == 0){
    return 0;
  }

  uint64_t ssl_ptr = (uint64_t) PT_REGS_PARM1(ctx);
  uint64_t wbio = (uint64_t) PT_REGS_PARM3(ctx);

  bpf_map_update_elem(&connection_bio_map, &wbio, &ssl_ptr, BPF_ANY);

  return 0;
}

SEC("uprobe/openssl_bio_write")
int probe_entry_bio_write (struct pt_regs* ctx) {
  uint64_t pid = get_curr_tgid_pid();
  if (pid == 0){
    return 0;
  }

  uint64_t bio = (uint64_t) PT_REGS_PARM1(ctx);

  uint64_t* ssl_ptr_ptr = bpf_map_lookup_elem(&connection_bio_map, &bio);
  if (ssl_ptr_ptr == NULL) {
    return 0;
  }

  uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, ssl_ptr_ptr);
  if (trace_conn != NULL && *trace_conn == 0) {
    return 0;
  }

  uint8_t *cntl = bpf_map_lookup_elem(&data_sample_cntl, ssl_ptr_ptr);
  if (cntl == NULL)  {
    return 0;
  }

  const char *ptr = (const char*) PT_REGS_PARM2(ctx);
  uint32_t len = (uint32_t)PT_REGS_PARM3(ctx);

  if (len < TLS_TOTAL_DATA_SIZE) {
    return 0;
  }
  const int kZero = 0;
  openssl_correlation * info = (openssl_correlation * )
      bpf_map_lookup_elem(&buffer_heap, &kZero);
  if (info == NULL){
    return 0;
  }
  info->mdata.type = kSslCorrelationInfo;
  info->mdata.conn_id = (uint64_t)*ssl_ptr_ptr;

  data_sample_t* sample = (data_sample_t*) info->info;
  sample->level = OPENSSL_LEVEL;

  if (bpf_probe_read(&sample->data, TLS_DATA_HASH_SIZE, &ptr[TLS_DATA_OFFSET])){
    return 0;
  }
  bpf_perf_event_output(ctx, &openssl_correlation_events, BPF_F_CURRENT_CPU,
                        info, sizeof(openssl_correlation));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
