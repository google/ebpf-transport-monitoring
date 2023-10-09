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
    name = "data_types",
    hdrs = ["data_types.h"],
)

cc_library(
    name = "handlers",
    hdrs = ["handlers.h"],
    deps = [
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "log_exporter",
    hdrs = ["log_exporter.h"],
    deps = [
        ":data_types",
        ":handlers",
        "//ebpf_monitor/correlator",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "metric_exporter",
    hdrs = ["metric_exporter.h"],
    deps = [
        ":data_types",
        ":handlers",
        "//ebpf_monitor/correlator",
        "@com_google_absl//absl/status",
    ],
)
