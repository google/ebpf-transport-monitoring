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

# This package contains code regarding the different eBPF code installed into the kernel.

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "tcp_source",
    srcs = ["tcp_source.cc"],
    hdrs = ["tcp_source.h"],
    deps = [
        "//ebpf_monitor/source",
        "//ebpf_monitor/source:data_ctx",
        "//ebpf_monitor/utils:source_helper",
        "@libbpf",
    ],
)

cc_library(
    name = "map_source",
    srcs = ["map_source.cc"],
    hdrs = ["map_source.h"],
    deps = [
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/source",
        "//ebpf_monitor/source:data_ctx",
        "//ebpf_monitor/utils:map_memory",
        "//ebpf_monitor/utils:source_helper",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@libbpf",
    ],
)

cc_library(
    name = "h2_go_grpc_source",
    srcs = [
        "h2_go_grpc_source.cc",
    ],
    hdrs = ["h2_go_grpc_source.h"],
    deps = [
        "//ebpf_monitor/source",
        "//ebpf_monitor/source:probes",
        "//ebpf_monitor/utils:dwarf_reader",
        "//ebpf_monitor/utils:elf_reader",
        "//ebpf_monitor/utils:proc_reader",
        "//ebpf_monitor/utils:sym_addrs",
        "//sources/common:defines",
        "//sources/common:syms",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_re2//:re2",
        "@libbpf",
    ],
)

cc_library(
    name = "openssl_source",
    srcs = [
        "openssl_source.cc",
    ],
    hdrs = ["openssl_source.h"],
    deps = [
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/source",
        "//ebpf_monitor/source:data_ctx",
        "//ebpf_monitor/source:probes",
        "//ebpf_monitor/utils:elf_reader",
        "//ebpf_monitor/utils:proc_reader",
        "//ebpf_monitor/utils:sym_addrs",
        "//sources/common:defines",
        "//sources/common:syms",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@libbpf",
    ],
)
