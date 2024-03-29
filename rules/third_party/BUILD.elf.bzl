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

"""The build rule for building elfutils."""

load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make")

filegroup(name = "elfutils_all", srcs = glob(["**"]), visibility = ["//visibility:public"])

configure_make(
    name = "libelf",
    lib_source = ":elfutils_all",
    configure_options = [
        "--disable-debuginfod",
        "--without-zstd",
    ],
    out_lib_dir = "lib",
    out_shared_libs = [
        "libelf.so",
        "libdw.so",
    ],
    out_static_libs = [
        "libdw.a",
        "libelf.a",
    ],
    visibility = ["//visibility:public"],
)
