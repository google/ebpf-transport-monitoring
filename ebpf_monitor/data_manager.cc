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

#include "ebpf_monitor/data_manager.h"

#include <iostream>
#include <memory>
#include <ostream>
#include <cstdlib>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "ebpf_monitor/exporter/handlers.h"
#include "ebpf_monitor/source/data_ctx.h"
#include "ebpf_monitor/utils/event_manager.h"

#include "event2/event.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

namespace ebpf_monitor {

#define PERF_PAGES 2
#define MAX_SIZE 1024

DataManager::DataManager() {
  struct event *event = nullptr;
  struct DataManagerCtx *data_ctx = new (struct DataManagerCtx);
  data_ctx->this_ = this;
  data_ctx->ctx = nullptr;
  event = event_new(EventManager::GetInstance().event_base(),
                    -1, EV_PERSIST, HandleCleanup, (void *)data_ctx);
  auto timeval = absl::ToTimeval(absl::Seconds(60));
  event_add(event, &timeval);
  events_.push_back(event);
}

absl::Status DataManager::Init() {
  // std::aligned_memory is defined in C++17. To avoid imposing this restriction
  // we align it manually

  // Need extra memory to store base_pointer and alignment offset
  memory_ = malloc(MAX_SIZE+15+sizeof(void*));
  if (memory_ == nullptr) {
    return absl::ResourceExhaustedError("Out of memory");
  }

  // ptr is not 16 bit aligned
  void *ptr = (void*)((uint64_t)((char*)memory_ + sizeof(void*)+15)
                      & ~(size_t)0x0F);
  // Storing value of memory from malloc in initial portion of ptr
  ((void**)ptr)[-1] = memory_;
  // assigning ptr to memory_ to use.
  memory_ = ptr;
  return absl::OkStatus();
}

absl::Status DataManager::RegisterLog(std::shared_ptr<DataCtx> ctx) {
  struct event *event = nullptr;
  struct DataManagerCtx *data_ctx = new (struct DataManagerCtx);
  data_ctx->this_ = this;
  data_ctx->ctx = ctx.get();
  event = event_new(EventManager::GetInstance().event_base(),
                    -1, EV_PERSIST, DataManager::HandleEvent,
                    (void *)data_ctx);
  auto buffer = perf_buffer__new(
      ctx->get_bpf_map_fd(), PERF_PAGES, DataManager::HandlePerf,
      DataManager::HandleLostEvents, data_ctx, nullptr);
  if (buffer == nullptr) {
    return absl::InternalError(
        absl::StrFormat("Cannot create perf_buffer %s", ctx->get_name()));
  }
  ctx->set_buffer(buffer);
  registered_sources_[ctx->get_name()] = true;
  auto timeval = absl::ToTimeval(ctx->get_poll());
  event_add(event, &timeval);
  events_.push_back(event);
  return absl::OkStatus();
}

absl::Status DataManager::RegisterMetric(std::shared_ptr<DataCtx> ctx) {
  struct event *event = nullptr;
  struct DataManagerCtx *data_ctx = new (struct DataManagerCtx);
  data_ctx->this_ = this;
  data_ctx->ctx = ctx.get();
  event = event_new(EventManager::GetInstance().event_base(),
                    -1, EV_PERSIST, HandleEvent, (void *)data_ctx);
  registered_sources_[ctx->get_name()] = true;
  auto timeval = absl::ToTimeval(ctx->get_poll());
  event_add(event, &timeval);
  events_.push_back(event);
  return absl::OkStatus();
}

absl::Status DataManager::Register(std::shared_ptr<DataCtx> ctx) {
  if (ctx->get_name().empty()) {
    return absl::InvalidArgumentError("ctx not initialized");
  }
  if (data_sources_.find(ctx->get_name()) != data_sources_.end()) {
    if (ctx->is_shared()) {
      return absl::OkStatus();
    }
    return absl::AlreadyExistsError(ctx->get_name());
  }
  data_sources_[ctx->get_name()] = ctx;
  if (ctx->is_internal()){
    return absl::OkStatus();
  }
  switch (ctx->get_type()) {
    case DataCtx::kLog:
      return RegisterLog(ctx);

    case DataCtx::kMetric:
      return RegisterMetric(ctx);

    case DataCtx::kUninitialized:
    default:
      return absl::InvalidArgumentError("ctx uninitialized");
  }

  return absl::OkStatus();
}

void DataManager::HandleLostEvents(void *ctx, int cpu, __u64 lost_cnt) {
  DataCtx *ptr = (DataCtx *)ctx;
  ptr->IncrementLostEvents(lost_cnt);
}

void DataManager::AddExternalLogHandler(LogHandlerInterface *log_handler) {
  ext_log_handlers_.push_back(log_handler);
}
void DataManager::AddExternalMetricHandler(
    MetricHandlerInterface *metric_handler) {
  ext_metric_handlers_.push_back(metric_handler);
}

absl::Status DataManager::AddLogHandler(
    absl::string_view name, std::shared_ptr<LogHandlerInterface> log_handler) {
  if (registered_sources_.find(name) == registered_sources_.end()) {
    auto status = RegisterLog(data_sources_[name]);
    if (!status.ok()) {
      return status;
    }
  }
  log_handlers_[name].push_back(log_handler);
  return absl::OkStatus();
}

absl::Status DataManager::AddMetricHandler(
    absl::string_view name,
    std::shared_ptr<MetricHandlerInterface> metric_handler) {
  if (registered_sources_.find(name) == registered_sources_.end()) {
    auto status = RegisterMetric(data_sources_[name]);
    if (!status.ok()) {
      return status;
    }
  }
  metric_handlers_[name].push_back(metric_handler);
  return absl::OkStatus();
}

void DataManager::HandlePerf(void *arg, int cpu, void *data, uint32_t data_sz) {
  const struct DataManagerCtx *d_ctx =
      static_cast<const struct DataManagerCtx *>(arg);
  struct DataCtx *ctx = static_cast<DataCtx *>(d_ctx->ctx);
  DataManager *this_ = (DataManager *)d_ctx->this_;

  if (data_sz >= MAX_SIZE) {
    std::cerr << "Data size received is greater than can be handled"
              << std::endl;
    return;
  }
  memcpy(this_->memory_, data, data_sz);
  if (ctx->is_internal() == false) {
    for (auto handler : this_->ext_log_handlers_) {
      auto status =
          handler->HandleData(ctx->get_name(), this_->memory_, data_sz);
      if (!status.ok()) {
        std::cerr << status << std::endl;
      }
    }
  }

  auto handler_it = this_->log_handlers_.find(ctx->get_name());
  if (handler_it != this_->log_handlers_.end()) {
    for (auto handler : handler_it->second) {
      auto status =
          handler->HandleData(ctx->get_name(), this_->memory_, data_sz);
      if (!status.ok()) {
        std::cerr << status << std::endl;
      }
    }
  }
}

void DataManager::ReadMap(const struct DataManagerCtx *d_ctx) {
  uint64_t key = 0;
  uint64_t data = 0;
  DataManager *this_ = (DataManager *)d_ctx->this_;
  struct DataCtx *ctx = static_cast<DataCtx *>(d_ctx->ctx);

  int err = bpf_map_get_next_key(ctx->get_bpf_map_fd(), nullptr, &key);
  if (err) return;
  do {
    bpf_map_lookup_elem(ctx->get_bpf_map_fd(), (void *)&key, (void *)&data);

    if (ctx->is_internal() == false) {
      for (auto handler : this_->ext_metric_handlers_) {
        auto status =
            handler->HandleData(ctx->get_name(), (void *)&key, (void *)&data);
        if (!status.ok()) {
          std::cerr << status << std::endl;
        }
      }
    }
    auto handler_it = this_->metric_handlers_.find(ctx->get_name());
    if (handler_it != this_->metric_handlers_.end()) {
      for (auto handler : handler_it->second) {
        auto status =
            handler->HandleData(ctx->get_name(), (void *)&key, (void *)&data);
        if (!status.ok()) {
          std::cerr << status << std::endl;
        }
      }
    }
  } while (bpf_map_get_next_key(ctx->get_bpf_map_fd(), &key, &key) == 0);
}

void DataManager::HandleEvent(evutil_socket_t, short, void *arg) {  // NOLINT
  struct DataManagerCtx *d_ctx = static_cast<struct DataManagerCtx *>(arg);
  struct DataCtx *ctx = static_cast<DataCtx *>(d_ctx->ctx);
  DataManager *this_ = (DataManager *)d_ctx->this_;
  switch (ctx->get_type()) {
    case DataCtx::kLog: {
      perf_buffer__consume(ctx->get_buffer());
      break;
    }
    case DataCtx::kMetric: {
      this_->ReadMap(d_ctx);
      break;
    }
    default:
      break;
  }
}

void DataManager::HandleCleanup(evutil_socket_t, short, void *arg) {  // NOLINT
  struct DataManagerCtx *d_ctx = static_cast<struct DataManagerCtx *>(arg);
  DataManager *this_ = (DataManager *)d_ctx->this_;
  absl::flat_hash_set<MetricHandlerInterface *> handlers;
  for (auto handler : this_->ext_metric_handlers_) {
    handler->Cleanup();
  }
  for (const auto &handler_it : this_->metric_handlers_) {
    for (const auto &handler : handler_it.second) {
      if (handlers.find(handler) != handlers.end()) {
        continue;
      }
      handlers.insert(handler.get());
      handler->Cleanup();
    }
  }
}

DataManager::~DataManager() {
  if (memory_ == nullptr) return;
  free(((void**) memory_)[-1]);
}

}  // namespace ebpf_monitor
