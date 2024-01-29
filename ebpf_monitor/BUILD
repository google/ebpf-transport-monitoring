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
    name = "data_manager",
    srcs = ["data_manager.cc"],
    hdrs = ["data_manager.h"],
    deps = [
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/exporter:handlers",
        "//ebpf_monitor/exporter:log_exporter",
        "//ebpf_monitor/exporter:metric_exporter",
        "//ebpf_monitor/source:data_ctx",
        "//ebpf_monitor/utils:event_manager",
        "@com_github_libevent_libevent//:libevent",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@libbpf",
    ],
)

cc_library(
    name = "ebpf_monitor",
    srcs = ["ebpf_monitor.cc"],
    hdrs = ["ebpf_monitor.h"],
    deps = [
        ":data_manager",
        "//correlators:h2_go_correlator",
        "//correlators:openssl_correlator",
        "//ebpf_monitor/correlator",
        "//ebpf_monitor/exporter:log_exporter",
        "//ebpf_monitor/exporter:metric_exporter",
        "//ebpf_monitor/source",
        "//ebpf_monitor/utils:event_manager",
        "//exporters:file_exporter",
        "//exporters:gcp_exporter",
        "//exporters:oc_gcp_exporter",
        "//exporters:stdout_event_logger",
        "//exporters:stdout_metric_exporter",
        "//sources/source_manager:h2_go_grpc_source",
        "//sources/source_manager:map_source",
        "//sources/source_manager:openssl_source",
        "//sources/source_manager:tcp_source",
        "//third_party/bpf_sources:sources",
        "@com_github_libevent_libevent//:libevent",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@zlib",
    ],
)
