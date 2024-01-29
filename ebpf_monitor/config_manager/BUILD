# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "config_server",
    srcs = ["config_server.cc"],
    hdrs = ["config_server.h"],
    deps = [
        ":proc_manager",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@net_http//net_http/public:shared_files",
        "@net_http//net_http/server/public:http_server",
        "@net_http//net_http/server/public:http_server_api",
    ],
)

cc_library(
    name = "proc_manager",
    srcs = ["proc_manager.cc"],
    hdrs = ["proc_manager.h"],
    deps = [
        "//ebpf_monitor",
        "//ebpf_monitor/utils:event_manager",
        "//ebpf_monitor/utils:proc_reader",
        "@com_github_libevent_libevent//:libevent",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)
