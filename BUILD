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

cc_library(
    name = "data_manager",
    srcs = ["data_manager.cc"],
    hdrs = ["data_manager.h"],
    deps = [
        "//ebpf_monitor/exporter:data_types",
        "//ebpf_monitor/exporter:handlers",
        "//ebpf_monitor/exporter:log_exporter",
        "//ebpf_monitor/exporter:metric_exporter",
        "//ebpf_monitor/source:data_ctx",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@libbpf",
        "@libevent",
    ],
)

cc_binary(
    name = "lightfoot",
    srcs = [
        "lightfoot.cc",
    ],
    linkstatic = True,
    deps = [
        ":data_manager",
        "//correlators:h2_go_correlator",
        "//correlators:openssl_correlator",
        "//ebpf_monitor/correlator",
        "//ebpf_monitor/exporter:log_exporter",
        "//ebpf_monitor/exporter:metric_exporter",
        "//ebpf_monitor/source",
        "//exporters:file_exporter",
        "//exporters:gcp_exporter",
        "//exporters:oc_gcp_exporter",
        "//exporters:stdout_event_logger",
        "//exporters:stdout_metric_exporter",
        "//sources/bpf_sources:sources",
        "//sources/source_manager:h2_go_grpc_source",
        "//sources/source_manager:map_source",
        "//sources/source_manager:openssl_source",
        "//sources/source_manager:tcp_source",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@libevent",
        "@zlib",
    ],
)
