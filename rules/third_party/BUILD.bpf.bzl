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

"""The build rule for building libbpf."""

load("@rules_foreign_cc//foreign_cc:defs.bzl", "make")

filegroup(name = "src", srcs = glob(["**"]), visibility = ["//visibility:public"])

filegroup(name = "lib_src", srcs = glob(["src/**"]), visibility = ["//visibility:public"])

make(
    name = "libbpf",
    # This is the library source. This filegroup includes the Makefile.
    lib_source = ":lib_src",
    build_data = [":src"],
    # This is the target passed to `make` (i.e., `make libbpf.a`).
    targets = ["install", "install_uapi_headers"],
    env = {
        "BUILD_STATIC_ONLY": "y",
        "DESTDIR": "$$INSTALLDIR$$",
        "CFLAGS": "-g -O2 -Werror -Wall -I$$EXT_BUILD_ROOT/external/libbpf/include -I$$EXT_BUILD_ROOT/external/libbpf/src -I$$EXT_BUILD_ROOT/external/libbpf/include/uapi",
    },
    args = ["V=1", "LIBDIR=/lib", "PREFIX=", "DESTDIR=$$INSTALLDIR$$", "INCLUDEDIR=/include", "UAPIDIR=/include", "TOPDIR=$$EXT_BUILD_ROOT/external/libbpf"],
    deps = [
        "@elfutils//:libelf",
        "@zlib//:zlib",
    ],
    out_include_dir = "include",
    visibility = ["//visibility:public"],
)
