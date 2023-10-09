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

# Exporters for lightfoot
package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "stdout_event_logger",
    srcs = ["stdout_event_logger.cc"],
    hdrs = ["stdout_event_logger.h"],
    deps = [
        ":exporters_util",
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/exporter:log_exporter",
        "//sources/common:defines",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "stdout_metric_exporter",
    srcs = ["stdout_metric_exporter.cc"],
    hdrs = ["stdout_metric_exporter.h"],
    deps = [
        ":exporters_util",
        "//:events",
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/exporter:metric_exporter",
        "//sources/common:defines",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "file_exporter",
    srcs = ["file_exporter.cc"],
    hdrs = ["file_exporter.h"],
    deps = [
        ":exporters_util",
        "//:events",
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/exporter:log_exporter",
        "//ebpf_monitor/exporter:metric_exporter",
        "//sources/common:defines",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
        "@spdlog",
    ],
)

cc_library(
    name = "gcp_exporter",
    srcs = ["gcp_exporter.cc"],
    hdrs = ["gcp_exporter.h"],
    deps = [
        ":exporters_util",
        ":gce_metadata",
        "//:events",
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/exporter:log_exporter",
        "//ebpf_monitor/exporter:metric_exporter",
        "//sources/common:defines",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@google_cloud_cpp//:logging",
    ],
)

cc_library(
    name = "exporters_util",
    srcs = ["exporters_util.cc"],
    hdrs = ["exporters_util.h"],
    deps = [
        "//:events",
        "//ebpf_monitor/exporter:data_types",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "gce_metadata",
    srcs = ["gce_metadata.cc"],
    hdrs = ["gce_metadata.h"],
    deps = [
        "@com_github_curl//:curl",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "oc_gcp_exporter",
    srcs = ["oc_gcp_exporter.cc"],
    hdrs = ["oc_gcp_exporter.h"],
    deps = [
        ":exporters_util",
        ":gce_metadata",
        "//:events",
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/exporter:metric_exporter",
        "@com_github_grpc_grpc//:grpc++_public_hdrs",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@io_opencensus_cpp//opencensus/exporters/stats/stackdriver:stackdriver_exporter",
        "@io_opencensus_cpp//opencensus/stats",
    ],
)
