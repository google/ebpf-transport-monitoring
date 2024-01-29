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
    name = "rules_proto",
    sha256 = "66bfdf8782796239d3875d37e7de19b1d94301e8972b3cbd2446b332429b4df1",
    strip_prefix = "rules_proto-4.0.0",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0.tar.gz",
        "https://github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0.tar.gz",
    ],
)
load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
rules_proto_dependencies()
rules_proto_toolchains()

http_archive(
  name = "com_google_absl",
  urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.1.tar.gz"],
  strip_prefix = "abseil-cpp-20230125.1",
  sha256 = "81311c17599b3712069ded20cca09a62ab0bf2a89dfa16993786c8782b7ed145"
)

http_archive(
  name = "com_google_re2",
  urls = ["https://github.com/google/re2/archive/refs/tags/2022-04-01.tar.gz"],
  strip_prefix = "re2-2022-04-01",
  sha256 = "1ae8ccfdb1066a731bba6ee0881baad5efd2cd661acd9569b689f2586e1a50e9"
)

http_archive(
    name = "rules_cc",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.4/rules_cc-0.0.4.tar.gz"],
    sha256 = "af6cc82d87db94585bceeda2561cb8a9d55ad435318ccb4ddfee18a43580fb5d",
    strip_prefix = "rules_cc-0.0.4",
)
http_archive(
    name = "google_cloud_cpp",
    strip_prefix = "google-cloud-cpp-2.8.0",
    url = "https://github.com/googleapis/google-cloud-cpp/archive/v2.8.0.tar.gz",
    sha256 = "21fb441b5a670a18bb16b6826be8e0530888d0b94320847c538d46f5a54dddbc"
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
    url = "https://sourceware.org/elfutils/ftp/0.189/elfutils-0.189.tar.bz2",
    strip_prefix = "elfutils-0.189",
    build_file = "//rules/third_party:BUILD.elf.bzl",
    sha256 = "39bd8f1a338e2b7cd4abc3ff11a0eddc6e690f69578a57478d8179b4148708c8",
)


git_repository(
    name = "libbpf",
    commit ="dc4e7076ad134559eb1051d353570f74cfd5606d",
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
    name = "zlib",
    url = "https://zlib.net/zlib-1.2.13.tar.gz",
    strip_prefix = "zlib-1.2.13",
    build_file = "//rules/third_party:BUILD.zlib.bzl",
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
    strip_prefix = "curl-master",
    urls = ["https://github.com/curl/curl/archive/master.zip"],
    sha256 = "7b7475703623a25b60d0a5bb26938f938fb5b64903a100380ec97bfa3ba79cb8",
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