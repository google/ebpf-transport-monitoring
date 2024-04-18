#ifndef _EBPF_MONITOR_CONFIG_MANAGER_proc_manager_H_
#define _EBPF_MONITOR_CONFIG_MANAGER_proc_manager_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "ebpf_monitor/config_manager/config_server.h"
#include "ebpf_monitor/config_manager/proc_manager.h"
#include "event2/event.h"
#include "net_http/server/public/httpserver_interface.h"

using net_http::ServerRequestInterface;

namespace ebpf_monitor {

class ProcHttpHandler {
 public:
  ProcHttpHandler(ConfigServer* server, ProcManager* proc_manager);
 private:
  void ProcessProcNameRequest(ServerRequestInterface* request);
  static void FindPids(evutil_socket_t, short, void *arg);  // NOLINT
  absl::flat_hash_map<std::string, std::string> containers_;
  ProcManager* proc_manager_;
  struct event_base *base_;
};

}  // namespace ebpf_monitor



#endif  // _EBPF_MONITOR_CONFIG_MANAGER_proc_manager_H_
