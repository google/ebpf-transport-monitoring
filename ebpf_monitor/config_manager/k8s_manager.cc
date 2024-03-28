#include "ebpf_monitor/config_manager/k8s_manager.h"

#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <string.h>
#include <memory>
#include <cstdio>
#include <sys/stat.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/types.h>

#include "absl/status/status.h"
#include "ebpf_monitor/utils/event_manager.h"
#include "absl/strings/string_view.h"
#include "absl/container/flat_hash_map.h"
#include "event2/event.h"
#include "net_http/public/response_code_enum.h"
#include "net_http/server/public/server_request_interface.h"
#include "ebpf_monitor/config_manager/config_server.h"
#include "ebpf_monitor/config_manager/proc_manager.h"
#include "absl/strings/str_split.h"

using net_http::HTTPStatusCode;

namespace ebpf_monitor {

typedef struct {
  K8sManager * self;
  std::string cri;
  std::string cid;
} __Cri;

bool isDirectory(const std::string& path) {
    struct stat sb;
    if (stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode)) {
        return true;
    }
    return false;
}

static std::vector<pid_t> CrioGetPIDs (std::string cid) {
  const std::string baseFolder = "/host/sys/fs/cgroup/kubepods.slice";
  const std::string kubepodsPrefix = "kubepods";
  std::string targetFolder;
  bool found = false;
  DIR* dir = opendir(baseFolder.c_str());
  if (dir) {
      struct dirent* entry;
      while ((entry = readdir(dir)) != NULL) {
          if (strcmp(entry->d_name, ".") == 0 ||
              strcmp(entry->d_name, "..") == 0) {
              continue;
          }
          std::string entryPath = baseFolder + "/" + entry->d_name;
          if (entryPath.find(kubepodsPrefix) != std::string::npos &&
              isDirectory(entryPath)) {
              targetFolder = entryPath +
                  "/crio-" + cid + ".scope";
              if (isDirectory(targetFolder)) {
                found = true;
                break;
              }
          }
      }
      closedir(dir);
  } else {
    std::cerr << "Error opening directory: " << baseFolder << std::endl;
    return {};
  }

  std::vector<pid_t> pids;
  if (found){
    std::ifstream procs(targetFolder+"/cgroup.procs");
    if (!procs.is_open()) {
      std::cerr << "Error opening file: "
          << targetFolder+"/cgroup.procs" << std::endl;
      return {};
    }
    std::string line;
    while (getline(procs, line)) {
        std::istringstream iss(line);
        int num;
        while (iss >> num) {
            pids.push_back(num);
        }
    }
    procs.close();
  }
  return pids;
}

void K8sManager::ProcessCriRequest(ServerRequestInterface* request) {
  absl::string_view type = request->http_method();
  auto content_type = request->GetRequestHeader("content-type");
  if (content_type.empty() || content_type != "text/plain") {
    request->ReplyWithStatus(HTTPStatusCode::BAD_REQUEST);
    return;
  }
  int64_t num_bytes = 0;
  auto body = request->ReadRequestBytes(&num_bytes);
  absl::string_view text = absl::string_view(body.get(), num_bytes);
  std::vector<std::string> lines = absl::StrSplit(text, '\n');

  if (type == "GET") {
    net_http::SetContentTypeTEXT(request);
    // Check if all the container exists.
    bool exists = false;
    for (const auto &cid : lines) {
      exists = containers_.find(cid) != containers_.end();
      fprintf(stderr, "lightfoot: handle GET request for |%s| exists: %d\n",
          cid.c_str(), exists);
      if (!exists) {
        break;
      }
    }

    if (exists) {
      request->ReplyWithStatus(HTTPStatusCode::OK);
    } else {
      request->ReplyWithStatus(HTTPStatusCode::NOT_FOUND);
    }
    return;
  }

  if (type == "POST") {
    for (const auto& cid : lines) {
      auto status = AddContainer("crio", cid);
      if (!status.ok()) {
        request->ReplyWithStatus(HTTPStatusCode::ERROR);
        return;
      }
    }
    request->ReplyWithStatus(HTTPStatusCode::OK);
    return;
  }

  net_http::SetContentTypeTEXT(request);
  request->WriteResponseString("Unknown request type");
  request->ReplyWithStatus(HTTPStatusCode::BAD_REQUEST);
}

K8sManager::K8sManager(ConfigServer* server,
                       ProcManager* proc_manager)
    : config_server_(server) , proc_manager_(proc_manager){
  base_ = EventManager::GetInstance().event_base();
  auto crio_handler = [this](ServerRequestInterface* request) {
    this->ProcessCriRequest(request);
  };
  config_server_->AddRequestHandler("/crio-id", crio_handler);
}

absl::Status K8sManager::AddContainer(std::string cri,
                                      std::string container_id) {
  containers_.insert({container_id, cri});
  __Cri *crio = new __Cri();
  crio->cri = cri;
  crio->cid = container_id;
  crio->self = this;
  int error = event_base_once(base_, -1, EV_TIMEOUT,
                              K8sManager::FindPids, crio, NULL);
  if (error != 0) {
    return absl::InternalError("event_base_once returned" +
                               std::to_string(error));
  }
  return absl::OkStatus();
}

void K8sManager::FindPids(evutil_socket_t, short, void *arg){ // NOLINT
  __Cri *cri = reinterpret_cast<__Cri *>(arg);
  std::vector<pid_t> pids;
  if (cri->cri == "crio") {
    pids = CrioGetPIDs(cri->cid);
  }
  cri->self->proc_manager_->AddPids(pids);
  delete cri;
}

}