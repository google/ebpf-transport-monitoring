# eBPF code for observability into network traffic
load("@rules_license//rules:license.bzl", "license")

package(
    default_applicable_licenses = [":license"],
    default_visibility = ["//visibility:public"],
)

license(
    name = "license",
    package_name = "ebpf_transport_monitoring",
)

licenses(["restricted"])

exports_files(
    ["LICENSE"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "events",
    hdrs = ["events.h"],
)

cc_binary(
    name = "lightfoot",
    srcs = [
        "lightfoot.cc",
    ],
    linkstatic = True,
    deps = [
        "//ebpf_monitor",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
    ],
)
