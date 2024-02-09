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

workspace(name = "lightfoot")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

http_archive(
    name = "rules_pkg",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
    ],
    sha256 = "8f9ee2dc10c1ae514ee599a8b42ed99fa262b757058f65ad3c384289ff70c4b8",
)
load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")
rules_pkg_dependencies()


http_archive(
  name = "com_googlesource_code_re2",
  urls = ["https://github.com/google/re2/releases/download/2023-11-01/re2-2023-11-01.tar.gz"],
  strip_prefix = "re2-2023-11-01",
)

http_archive(
    name = "zlib",
    url = "https://zlib.net/zlib-1.3.1.tar.gz",
    strip_prefix = "zlib-1.3.1",
    build_file = "//rules/third_party:BUILD.zlib.bzl",
)

http_archive(
    name = "rules_cc",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.4/rules_cc-0.0.4.tar.gz"],
    sha256 = "af6cc82d87db94585bceeda2561cb8a9d55ad435318ccb4ddfee18a43580fb5d",
    strip_prefix = "rules_cc-0.0.4",
)
http_archive(
    name = "google_cloud_cpp",
    strip_prefix = "google-cloud-cpp-2.16.0",
    url = "https://github.com/googleapis/google-cloud-cpp/archive/v2.16.0.tar.gz",
)

# Load indirect dependencies due to
#     https://github.com/bazelbuild/bazel/issues/1943
load("@google_cloud_cpp//bazel:google_cloud_cpp_deps.bzl", "google_cloud_cpp_deps")

google_cloud_cpp_deps()

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,
    grpc = True,
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")

grpc_extra_deps()

http_archive(
    name = "rules_foreign_cc",
    sha256 = "2a4d07cd64b0719b39a7c12218a3e507672b82a97b98c6a89d38565894cf7c51",
    strip_prefix = "rules_foreign_cc-0.9.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/refs/tags/0.9.0.tar.gz",
)

http_archive(
    name = "rules_license",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_license/releases/download/0.0.7/rules_license-0.0.7.tar.gz",
        "https://github.com/bazelbuild/rules_license/releases/download/0.0.7/rules_license-0.0.7.tar.gz",
    ],
    sha256 = "4531deccb913639c30e5c7512a054d5d875698daeb75d8cf90f284375fe7c360",
)

http_archive(
    name = "com_google_googletest",
    strip_prefix = "googletest-main",
    urls = ["https://github.com/google/googletest/archive/main.zip"],
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies()

http_archive(
    name = "elfutils",
    url = "https://sourceware.org/elfutils/ftp/0.190/elfutils-0.190.tar.bz2",
    strip_prefix = "elfutils-0.190",
    build_file = "//rules/third_party:BUILD.elf.bzl",
)


git_repository(
    name = "libbpf",
    commit ="20c0a9e3d7e7d4aeb283eae982543c9cacc29477",
    remote = "https://github.com/libbpf/libbpf.git",
    build_file = "//rules/third_party:BUILD.bpf.bzl",
)

git_repository(
    name = "net_http",
    commit = "55ac2986f5d3b64b21b642b49bf29ac6797d9457",
    remote = "https://github.com/google/net_http.git",
)

http_archive(
    name = "com_github_libevent_libevent",
    url = "https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz",
    sha256 = "92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb",
    strip_prefix = "libevent-2.1.12-stable",
    build_file = "//rules/third_party:BUILD.event.bzl",
)

http_archive(
    name = "com_github_tclap_tclap",
    url = "https://sourceforge.net/projects/tclap/files/tclap-1.4.0-rc1.tar.bz2",
    sha256 = "33e18c7828f76a9e5f2a00afe575156520e383693059ca9bc34ff562927e20c6",
    strip_prefix = "tclap-1.4.0-rc1",
    build_file = "//rules/third_party:BUILD.tclap.bzl",
)

http_archive(
    name = "com_github_curl",
    build_file = "//rules/third_party:BUILD.curl.bzl",
    strip_prefix = "curl-8.2.1",
    urls = ["https://github.com/curl/curl/releases/download/curl-8_2_1/curl-8.2.1.zip"],
    sha256 = "f28ce6b38cf798e3c52017162e5355705bb6717288d5faf3f57a950dac72d12d"
)

http_archive(
    name = "com_github_libarchive",
    build_file = "//rules/third_party:BUILD.libarchive.bzl",
    sha256 = "ba6d02f15ba04aba9c23fd5f236bb234eab9d5209e95d1c4df85c44d5f19b9b3",
    strip_prefix = "libarchive-3.6.2",
    urls = ["https://github.com/libarchive/libarchive/releases/download/v3.6.2/libarchive-3.6.2.tar.gz"],
)

http_archive(
    name = "spdlog",
    url = "https://github.com/gabime/spdlog/archive/refs/tags/v1.11.0.tar.gz",
    strip_prefix = "spdlog-1.11.0",
    build_file = "//rules/third_party:BUILD.spdlog.bzl",
    sha256 = "ca5cae8d6cac15dae0ec63b21d6ad3530070650f68076f3a4a862ca293a858bb"
)