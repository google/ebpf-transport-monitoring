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
#include "correlator_types.h"
#include "defines.h"
#include "events.h"
#include "h2_symaddrs.h"
#include "sym_helpers.h"
#include "sym_addrs.h"
#include "maps.h"
#include "parse_h2_frame.h"

typedef const h2_cfg_t config_type_t;

/* h2_grpc_pid_filter is a map of pids that the probe is supposed to trace */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u8));
  __uint(max_entries, MAX_PID_TRACED);
} h2_grpc_pid_filter SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(h2_cfg_t));
  __uint(max_entries, MAX_PID_TRACED);
} h2_cfg SEC(".maps");

/* h2_grpc_correlation is the buffer that is used to communicate events with
userspace for correlation related information.*/
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} h2_grpc_correlation SEC(".maps");

struct h2_conn_info{
  __u64 conn_id;
  __u8 client;
};

/* This struct keeps track of bufWriter to H2Connection */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(struct h2_conn_info));
  __uint(max_entries, MAX_H2_CONN_TRACED);
} buff_writer_to_h2_conn SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(correlator_ip_t));
  __uint(max_entries, 1);
} h2_cip_heap SEC(".maps");

static __always_inline uint32_t get_curr_pid() {
  uint32_t ppid = (bpf_get_current_pid_tgid() >> 32);
  uint8_t* trace_pid = bpf_map_lookup_elem(&h2_grpc_pid_filter, &ppid);
  if (unlikely(trace_pid == NULL)) {
    return 0;
  }
  return ppid;
}

static __always_inline config_type_t * get_configuration(uint64_t pid){
  return bpf_map_lookup_elem(&h2_cfg, &pid);
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

static __always_inline int get_tcp_tuple_from_h2_conn(void * ctx,
                                                config_type_t * configuration,
                                                void * h2_conn,
                                                __u8 client){
  struct go_interface g_laddr, g_raddr;
  struct go_slice ip;
  int port;
  member_var_t laddr;
  member_var_t raddr;

  if (client) {
    REQUIRE_MEM_VAR(configuration->offset.client_laddr, g_laddr);
    laddr = configuration->offset.client_laddr;
    REQUIRE_MEM_VAR(configuration->offset.client_raddr, g_raddr);
    raddr = configuration->offset.client_raddr;
  } else {
    REQUIRE_MEM_VAR(configuration->offset.server_laddr, g_laddr);
    laddr = configuration->offset.server_laddr;
    REQUIRE_MEM_VAR(configuration->offset.server_raddr, g_raddr);
    raddr = configuration->offset.server_raddr;
  }

  REQUIRE_MEM_VAR(configuration->offset.tcp_ip, ip);
  REQUIRE_MEM_VAR(configuration->offset.tcp_port, port);

  int64_t success = READ_MEMBER(h2_conn, laddr, &g_laddr);
  if (success < 0 || g_laddr.ptr == NULL) {
    return 0;
  }

  success = READ_MEMBER(h2_conn, raddr, &g_raddr);
  if (success < 0 || g_raddr.ptr == NULL) {
    return 0;
  }

  if (unlikely(g_laddr.type != configuration->types.tcp_addr ||
              g_raddr.type != configuration->types.tcp_addr)){
    return 0;
  }

  success = READ_MEMBER(g_laddr.ptr, configuration->offset.tcp_ip, &ip);
  READ_MEMBER(g_laddr.ptr, configuration->offset.tcp_port, &port);
  if (unlikely(success < 0 || ip.len < 0 || ip.ptr == NULL)) {
    return 0;
  }

  const int kZero = 0;
  correlator_ip_t * cip = bpf_map_lookup_elem(&h2_cip_heap, &kZero);
  if (unlikely(cip == NULL)){
    return 0;
  }

  __builtin_memset(cip, 0, sizeof(correlator_ip_t));
  cip->conn_id = (uint64_t) h2_conn;
  cip->lport = port;

  /* Due to compiler optimizations the bpf verifier rejects the program.
  The addition of asm volatile makes sure that the code is not optimized by the
  compiler.*/
  size_t length = ip.len;
  size_t length_minus_1 = length - 1;
  asm volatile("" : "+r"(length_minus_1) :);
  length = length_minus_1 + 1;

  if (length_minus_1 < CORRELATOR_IP_MAX) {
    cip->llen = ip.len;
    bpf_probe_read(&cip->laddr, length, ip.ptr);
  }

  success = READ_MEMBER(g_raddr.ptr, configuration->offset.tcp_ip, &ip);
  READ_MEMBER(g_raddr.ptr, configuration->offset.tcp_port, &port);
  if (unlikely(success < 0 || ip.len < 0 || ip.ptr == NULL)) {
    return 0;
  }
  cip->rport = port;

  length = ip.len;
  length_minus_1 = length - 1;
  asm volatile("" : "+r"(length_minus_1) :);
  length = length_minus_1 + 1;

  if (length_minus_1 < CORRELATOR_IP_MAX) {
    cip->rlen = ip.len;
    bpf_probe_read(&cip->raddr, length, ip.ptr);
  }

  bpf_perf_event_output(ctx, &h2_grpc_correlation, BPF_F_CURRENT_CPU,
                        cip, sizeof(correlator_ip_t));
  return 0;
}

static __always_inline int send_h2_start(void * ctx,
                                        config_type_t * configuration,
                                        ec_ebpf_events_t * event,
                                        void * h2_conn,
                                        __u8 client){
  metric_format_t format = {.data = 0, .timestamp = event->mdata.timestamp};
  event->mdata.length = 0;
  event->mdata.event_type = EC_H2_EVENT_START;
  uint64_t conn_id = event->mdata.connection_id;
  uint64_t timestamp = event->mdata.timestamp;
  bpf_map_update_elem(&h2_connection, &conn_id,
                      &timestamp, BPF_ANY);
  bpf_map_update_elem(&h2_stream_count, &conn_id,
                      &format, BPF_ANY);
  bpf_map_update_elem(&h2_reset_stream_count, &conn_id,
                      &format, BPF_ANY);
  bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU, event,
                        sizeof(ec_ebpf_event_metadata_t) + 0);

  void * framer_ptr = 0;
  if (client) {
    REQUIRE_MEM_VAR(configuration->offset.client_framer, framer_ptr);
    READ_MEMBER(h2_conn, configuration->offset.client_framer, &framer_ptr);
  } else {
    REQUIRE_MEM_VAR(configuration->offset.server_framer, framer_ptr);
    READ_MEMBER(h2_conn, configuration->offset.server_framer,
                &framer_ptr);
  }

  if (framer_ptr == NULL){
    return -1;
  }

  get_tcp_tuple_from_h2_conn(ctx, configuration, h2_conn, client);

  uint64_t buffer_ptr;
  REQUIRE_MEM_VAR(configuration->offset.framer_bufwriter, buffer_ptr);
  READ_MEMBER(framer_ptr, configuration->offset.framer_bufwriter,
                &buffer_ptr);
  // This can cause a collision in case we are tracking multiple PIDs.
  // Not handling for now.
  struct h2_conn_info conn_info;
  __builtin_memset(&conn_info, 0, sizeof(struct h2_conn_info));
  conn_info.conn_id = conn_id;
  conn_info.client = client;
  bpf_map_update_elem(&buff_writer_to_h2_conn, &buffer_ptr,
                      &conn_info, BPF_ANY);
  return 0;
}


static __always_inline int send_h2_go_away (void * ctx,
                                     config_type_t * configuration,
                                     ec_ebpf_events_t * event,
                                     void * frame_ptr){
  ec_h2_go_away_t * data = (ec_h2_go_away_t*)event->event_info;
  event->mdata.event_type = EC_H2_EVENT_GO_AWAY;

  REQUIRE_MEM_VAR(configuration->offset.goawayframe_stream,
                  data->mdata.last_stream_id);
  READ_MEMBER(frame_ptr, configuration->offset.goawayframe_stream,
              &data->mdata.last_stream_id);
  REQUIRE_MEM_VAR(configuration->offset.goawayframe_error,
                  data->mdata.error_code);
  READ_MEMBER(frame_ptr, configuration->offset.goawayframe_error,
              &data->mdata.error_code);
  struct go_slice slice;

  REQUIRE_MEM_VAR(configuration->offset.goawayframe_data, slice);
  int64_t success = bpf_probe_read(&slice, sizeof(slice), frame_ptr +
                 configuration->offset.goawayframe_data.offset);
  if (unlikely((success < 0 || slice.len <= 0 || slice.ptr == NULL))) {
    event->mdata.length = sizeof(ec_h2_go_away_mdata_t);
    bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU, event,
                        sizeof(ec_ebpf_event_metadata_t) +
                        sizeof(ec_h2_go_away_mdata_t));
    return 0;
  }

  // Following lines are needed on some compilers and environments to
  // satisfy the bpf verifier.
  size_t length = slice.len;
  size_t length_minus_1 = length - 1;
  asm volatile("" : "+r"(length_minus_1) :);
  length = length_minus_1 + 1;

  uint8_t * debug_data = (uint8_t *)data->debug_data;
  if (length > EC_MAX_GO_AWAY_DATA_SIZE){
    length = EC_MAX_GO_AWAY_DATA_SIZE;
  }

  success = bpf_probe_read(debug_data, (uint32_t) length, slice.ptr);
  if (unlikely((success < 0 || slice.len <= 0 || slice.ptr == NULL))) {
    event->mdata.length = sizeof(ec_h2_go_away_mdata_t);
    bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU, event,
                        sizeof(ec_ebpf_event_metadata_t) +
                        sizeof(ec_h2_go_away_mdata_t));
    return 0;
  }
  event->mdata.length = length + sizeof(ec_h2_go_away_mdata_t);
  uint64_t data_length = event->mdata.length + sizeof(ec_ebpf_event_metadata_t);
  if (unlikely(data_length > sizeof(ec_ebpf_events_t))){
    data_length = sizeof(ec_ebpf_events_t);
  }
  bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU,
                        event, data_length);
  return 0;
}

static __always_inline int send_h2_settings (void * ctx,
                                      config_type_t * configuration,
                                      ec_ebpf_events_t * event,
                                      void * frame_ptr){
  struct go_slice slice;
  char * settings = (char *)event->event_info;
  REQUIRE_MEM_VAR(configuration->offset.settingsframe_data, slice);
  int64_t success = bpf_probe_read(&slice, sizeof(slice), frame_ptr +
                 configuration->offset.settingsframe_data.offset);
  if (unlikely((success < 0 || slice.len < 0 || slice.ptr == NULL))) {
    return 0;
  }
  size_t length = slice.len;
  size_t length_minus_1 = length - 1;
  asm volatile("" : "+r"(length_minus_1) :);
  length = length_minus_1 + 1;

  if (likely(length_minus_1 < EC_MAX_EVENT_DATA_SIZE)) {
    bpf_probe_read(settings, (uint32_t) length, slice.ptr);
    event->mdata.event_type = EC_H2_EVENT_SETTINGS;
    uint64_t data_length = length + sizeof(ec_ebpf_event_metadata_t);
    if (unlikely(data_length > sizeof(ec_ebpf_events_t))){
      data_length = sizeof(ec_ebpf_events_t);
    }
    bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU,
                          event, data_length);
  }
  return 0;
}

static __always_inline int collect_data(__u8 client, struct pt_regs* ctx) {
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }

  config_type_t * configuration = get_configuration(pid);
  if (unlikely(configuration == NULL)){
    return 0;
  }

  REQUIRE_SYM_LOC(configuration->variables.connection);
  REQUIRE_SYM_LOC(configuration->variables.frame);

  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }

  event->mdata.sent_recv = 1;

  const void* sp = (const void*)PT_REGS_SP(ctx);
  uint64_t* regs = go_regabi_regs(ctx);
  if (unlikely(regs == NULL)) {
    return 0;
  }

  void* conn_ptr = 0;
  int64_t success = 0;
  success = read_variable(&conn_ptr, sizeof(conn_ptr),
                &configuration->variables.connection, sp, regs);

  if (unlikely(success < 0)){
    return -1;
  }

  void* frame_ptr = 0;
  success = read_variable(&frame_ptr, sizeof(frame_ptr),
                &configuration->variables.frame, sp, regs);
  if (unlikely(success < 0)){
    return -1;
  }

  uint64_t *value = bpf_map_lookup_elem(&h2_connection, &conn_ptr);
  event->mdata.connection_id = (uint64_t) conn_ptr;
  if (value == NULL){
    send_h2_start(ctx, configuration, event, conn_ptr, client);
  } else {
    uint64_t timestamp = event->mdata.timestamp;
    *value = timestamp;
  }
  uint8_t type;
  REQUIRE_MEM_VAR(configuration->offset.frameheader_type, type);
  success = READ_MEMBER(frame_ptr,
                      configuration->offset.frameheader_type, &type);
  if (unlikely(success < 0)){
    return -1;
  }

  uint32_t stream_id;
  REQUIRE_MEM_VAR(configuration->offset.frameheader_streamid, stream_id);
  success = READ_MEMBER(frame_ptr,
                        configuration->offset.frameheader_streamid,
                        &stream_id);
  if (unlikely(success < 0)){
    return -1;
  }

  switch (type) {
    case H2_RST_STREAM: {
      uint32_t error = 0;
      REQUIRE_MEM_VAR(configuration->offset.rstframe_error, error);
      success = READ_MEMBER(frame_ptr, configuration->offset.rstframe_error,
                  &error);
      if (unlikely(success < 0)){
        return -1;
      }
      send_h2_reset(ctx, event, stream_id, error);
      break;
    }
    case H2_SETTINGS:
      send_h2_settings(ctx, configuration, event, frame_ptr);
      break;
    case H2_PING:
      // send_h2_ping(ctx, configuration, event, frame_ptr);
      return 0;
    case H2_GOAWAY:
      send_h2_go_away(ctx, configuration, event, frame_ptr);
      return 0;

    case H2_WINDOW_UPDATE:
      // send_h2_window_update(ctx, event, frame_ptr);
      return 0;
    case H2_DATA:
    default:
      break;
  }

  uint8_t flag;
  REQUIRE_MEM_VAR(configuration->offset.frameheader_flags, flag);
  READ_MEMBER(frame_ptr, configuration->offset.frameheader_flags, &flag);

  if ((flag & H2_END_STREAM) != 0){
    send_h2_end(ctx, event, stream_id);
  }

  return 0;
}

static __always_inline int collect_header_data(__u8 client,
                                               struct pt_regs* ctx){
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }

  config_type_t * configuration = get_configuration(pid);
  if (unlikely(configuration == NULL)){
    return 0;
  }
  REQUIRE_SYM_LOC(configuration->variables.connection);
  REQUIRE_SYM_LOC(configuration->variables.frame);

  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }

  event->mdata.sent_recv = 1;

  const void* sp = (const void*)PT_REGS_SP(ctx);
  uint64_t* regs = go_regabi_regs(ctx);
  if (unlikely(regs == NULL)) {
    return 0;
  }

  void * conn_ptr = 0;
  int64_t success = 0;
  success = read_variable(&conn_ptr, sizeof(conn_ptr),
                &configuration->variables.connection, sp, regs);
  if (unlikely(success < 0)){
    return -1;
  }

  void* meta_header_frame = 0;
  success = read_variable(&meta_header_frame, sizeof(meta_header_frame),
                &configuration->variables.frame, sp, regs);
  if (unlikely(success < 0)){
    return -1;
  }

  void * frame_ptr = 0;
  success = bpf_probe_read(&frame_ptr, sizeof(frame_ptr), meta_header_frame);
  if (unlikely(success < 0)){
    return -1;
  }

  uint64_t *value = bpf_map_lookup_elem(&h2_connection, &conn_ptr);
  event->mdata.connection_id = (uint64_t) conn_ptr;
  if (unlikely(value == NULL)){
    send_h2_start(ctx, configuration, event, conn_ptr, client);
  } else {
    uint64_t timestamp = event->mdata.timestamp;
    *value =  timestamp;
  }

  uint32_t stream_id;
  REQUIRE_MEM_VAR(configuration->offset.frameheader_streamid, stream_id);
  READ_MEMBER(frame_ptr, configuration->offset.frameheader_streamid,
            &stream_id);
  // In case of client we capture start of sending stream on send side.
  if (client == 0) {
    send_h2_headers(ctx, event, stream_id);
  }

  uint8_t flag;
  REQUIRE_MEM_VAR(configuration->offset.frameheader_flags, flag);
  READ_MEMBER(frame_ptr, configuration->offset.frameheader_flags, &flag);
  if ((flag & H2_END_STREAM) != 0){
    send_h2_end(ctx, event, stream_id);
  }
  return 0;
}

static int __always_inline process_frame(struct pt_regs* ctx) {
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }

  config_type_t * configuration = get_configuration(pid);
  if (unlikely(configuration == NULL)){
    return 0;
  }

  REQUIRE_SYM_LOC(configuration->variables.buf_writer);
  REQUIRE_SYM_LOC(configuration->variables.write_buffer_len);
  REQUIRE_SYM_LOC(configuration->variables.write_buffer_ptr);

  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }

  event->mdata.sent_recv = 0;

  const void* sp = (const void*)PT_REGS_SP(ctx);
  uint64_t* regs = go_regabi_regs(ctx);
  if (unlikely(regs == NULL)) {
    return 0;
  }
  void * buf_writer = 0;
  int64_t success = 0;
  success = read_variable(&buf_writer, sizeof(buf_writer),
                &configuration->variables.buf_writer, sp, regs);
  if (unlikely(success != 0)) {
    return success;
  }

  uint64_t len = 0;
  success = read_variable(&len, sizeof(len),
                &configuration->variables.write_buffer_len, sp, regs);
  if (unlikely(success < 0)) {
    return success;
  }
  if (len <= 0) {
    return 0;
  }
  char* buf_ptr = 0;
  success = read_variable(&buf_ptr , sizeof(buf_ptr),
                &configuration->variables.write_buffer_ptr, sp, regs);
  if (unlikely(success  < 0)){
    return success;
  }
  // What do you do if you don't have connection pointer corresponding to
  // h2 connection. This should ideally only happen if client has not received
  // any message from this connection.
  // Settings frame could be missed in this case.

  struct h2_conn_info * h2_connection =
      bpf_map_lookup_elem(&buff_writer_to_h2_conn, &buf_writer);
  if (h2_connection == NULL) {
    // Figure out what to do, return for now.
    return 0;
  } else {
    event->mdata.connection_id = h2_connection->conn_id;
  }
  return parse_h2_frame(ctx, buf_ptr, len, event, h2_connection->client);
}

/*
All these functions have the similar function signature.
Hence we can use the same function to process the information.
The type of frame can be figured out from the frame itself.
*/
SEC("uprobe/h2_server_probe")
int probe_handle_server_data(struct pt_regs* ctx) {
  return collect_data(FALSE, ctx);
}


SEC("uprobe/h2_client_probe")
int probe_handle_client_data(struct pt_regs* ctx) {
  return collect_data(TRUE, ctx);
}

SEC("uprobe/h2_server_header_probe")
int probe_handle_server_header(struct pt_regs* ctx) {
  return collect_header_data(FALSE, ctx);
}

SEC("uprobe/h2_server_header_probe")
int probe_handle_client_header(struct pt_regs* ctx) {
  return collect_header_data(TRUE, ctx);
}

/* Note it is possible that we cannot find a corresponding h2 connection id for
a bufwriter for a few frames on client side this is accepted.
Will fix it in the next revision.
*/
SEC("uprobe/h2_bufwriter_probe")
int probe_sent_frame(struct pt_regs* ctx) {
  return process_frame(ctx);
}

SEC("uprobe/h2_close_probe")
int probe_close(struct pt_regs* ctx){
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }

  config_type_t * configuration = get_configuration(pid);
  if (unlikely(configuration == NULL)){
    return 0;
  }
  REQUIRE_SYM_LOC(configuration->variables.connection);

  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }

  event->mdata.sent_recv = 1;

  const void* sp = (const void*)PT_REGS_SP(ctx);
  uint64_t* regs = go_regabi_regs(ctx);
  if (unlikely(regs == NULL)) {
    return 0;
  }

  void* conn_ptr = 0;
  int64_t success = 0;
  success = read_variable(&conn_ptr, sizeof(conn_ptr),
                &configuration->variables.connection, sp, regs);
  if (unlikely(success < 0)){
    return -1;
  }

  uint64_t *value = bpf_map_lookup_elem(&h2_connection, &conn_ptr);
  event->mdata.connection_id = (uint64_t) conn_ptr;
  if (unlikely(value == NULL)){
    return 0;
  }
  bpf_map_delete_elem(&h2_connection, &conn_ptr);

  event->mdata.length = 0;
  event->mdata.event_type = EC_H2_EVENT_CLOSE;
  bpf_perf_event_output(ctx, &h2_events, BPF_F_CURRENT_CPU, event,
                              sizeof(ec_ebpf_event_metadata_t));
  return 0;
}
char LICENSE[] SEC("license") = "GPL";
