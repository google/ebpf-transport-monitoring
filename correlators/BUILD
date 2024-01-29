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
    name = "h2_go_correlator",
    srcs = ["h2_go_correlator.cc"],
    hdrs = ["h2_go_correlator.h"],
    deps = [
        "//:events",
        "//ebpf_monitor/correlator",
        "//ebpf_monitor/source:data_ctx",
        "//sources/common:correlator_types",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "dummy_correlator",
    srcs = ["dummy_correlator.cc"],
    hdrs = ["dummy_correlator.h"],
    deps = [
        "//ebpf_monitor/correlator",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "openssl_correlator",
    srcs = ["openssl_correlator.cc"],
    hdrs = ["openssl_correlator.h"],
    deps = [
        "//:events",
        "//ebpf_monitor/correlator",
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/source:data_ctx",
        "//ebpf_monitor/utils:event_manager",
        "//sources/common:correlator_types",
        "@com_github_libevent_libevent//:libevent",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)
