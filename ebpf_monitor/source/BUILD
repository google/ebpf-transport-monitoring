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
    name = "btf_min",
    deps = [":reduced_btf"],
    alwayslink = True,
)

genrule(
    name = "reduced_btf",
    srcs = ["reduced_btfs.tar.gz"],
    outs = ["reduced_btf.o"],
    cmd = "$(LD) -r -b binary $(locations reduced_btfs.tar.gz) -m elf_x86_64 -o $@",
    toolchains = [
        "@bazel_tools//tools/cpp:current_cc_toolchain",
    ],
)

cc_library(
    name = "probes",
    hdrs = ["probes.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@libbpf",
    ],
)

cc_library(
    name = "data_ctx",
    hdrs = ["data_ctx.h"],
    deps = [
        "//ebpf_monitor/exporter:data_types",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@libbpf",
    ],
)

cc_library(
    name = "source",
    srcs = ["source.cc"],
    hdrs = ["source.h"],
    deps = [
        ":btf_min",
        ":data_ctx",
        ":probes",
        "//ebpf_monitor/utils:map_memory",
        "//ebpf_monitor/utils:source_helper",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@libbpf",
    ],
)
