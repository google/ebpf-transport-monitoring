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
    name = "event_manager",
    hdrs = ["event_manager.h"],
    deps = [
        "@com_github_libevent_libevent//:libevent",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "archive_handler",
    srcs = ["archive_handler.cc"],
    hdrs = ["archive_handler.h"],
    deps = [
        "@com_github_libarchive//:libarchive",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "utils",
    hdrs = ["utils.h"],
)

cc_library(
    name = "sym_addrs",
    hdrs = ["sym_addrs.h"],
)

cc_library(
    name = "map_memory",
    hdrs = ["map_memory.h"],
    deps = [
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "os_helper",
    srcs = ["os_helper.cc"],
    hdrs = ["os_helper.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_re2//:re2",
    ],
)

cc_library(
    name = "elf_reader",
    srcs = ["elf_reader.cc"],
    hdrs = ["elf_reader.h"],
    deps = [
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@elfutils//:libelf",
    ],
)

cc_library(
    name = "dwarf_reader",
    srcs = ["dwarf_reader.cc"],
    hdrs = ["dwarf_reader.h"],
    deps = [
        ":sym_addrs",
        ":utils",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
        "@elfutils//:libelf",
    ],
)

cc_library(
    name = "source_helper",
    srcs = ["source_helper.cc"],
    hdrs = ["source_helper.h"],
    deps = [
        ":archive_handler",
        ":dwarf_reader",
        ":elf_reader",
        ":os_helper",
        ":proc_reader",
        ":utils",
        "//third_party/bpf_sources:sources_obj",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_re2//:re2",
        "@libbpf",
    ],
)

cc_library(
    name = "proc_reader",
    srcs = ["proc_reader.cc"],
    hdrs = ["proc_reader.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)
