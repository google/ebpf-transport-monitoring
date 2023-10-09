load("//rules:bpf.bzl", "bpf_program")
load("@rules_pkg//:pkg.bzl", "pkg_tar")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "missing_headers",
    hdrs = [
        "missing_defs.h",
        "struct_flavors.h",
    ],
)

cc_library(
    name = "vmlinux",
    hdrs = ["vmlinux.h"],
)

cc_library(
    name = "maps",
    hdrs = [
        "maps.h",
    ],
)

cc_library(
    name = "parse_h2_frame",
    hdrs = [
        "parse_h2_frame.h",
    ],
)

cc_library(
    name = "sym_helpers",
    hdrs = [
        "sym_helpers.h",
    ],
)

bpf_program(
    name = "tcp_bpf_core",
    src = "tcp_bpf.c",
    core = True,
    deps = [
        ":maps",
        ":missing_headers",
        ":vmlinux",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "@libbpf",
    ],
)

bpf_program(
    name = "tcp_bpf",
    src = "tcp_bpf.c",
    core = False,
    deps = [
        ":maps",
        "//:events",
        "//external_libs/include:stdarg",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "@libbpf",
    ],
)

bpf_program(
    name = "tcp_bpf_kprobe_core",
    src = "tcp_bpf_kprobe.c",
    core = True,
    deps = [
        ":missing_headers",
        ":vmlinux",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "@libbpf",
    ],
)

bpf_program(
    name = "tcp_bpf_kprobe",
    src = "tcp_bpf_kprobe.c",
    core = False,
    deps = [
        "//:events",
        "//external_libs/include:stdarg",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "@libbpf",
    ],
)

bpf_program(
    name = "h2_bpf_core",
    src = "h2_bpf.c",
    core = True,
    deps = [
        ":maps",
        ":missing_headers",
        ":parse_h2_frame",
        ":sym_helpers",
        ":vmlinux",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "@libbpf",
    ],
)

bpf_program(
    name = "h2_bpf",
    src = "h2_bpf.c",
    core = False,
    deps = [
        ":maps",
        ":parse_h2_frame",
        ":sym_helpers",
        "//:events",
        "//external_libs/include:stdarg",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "@libbpf",
    ],
)

bpf_program(
    name = "openssl_core",
    src = "openssl_bpf.c",
    core = True,
    deps = [
        ":maps",
        ":missing_headers",
        ":parse_h2_frame",
        ":sym_helpers",
        ":vmlinux",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "@libbpf",
    ],
)

bpf_program(
    name = "openssl_bpf",
    src = "openssl_bpf.c",
    core = False,
    deps = [
        ":maps",
        ":parse_h2_frame",
        ":sym_helpers",
        "//:events",
        "//external_libs/include:stdarg",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "@libbpf",
    ],
)

bpf_program(
    name = "maps_core",
    src = "maps.c",
    core = True,
    deps = [
        ":maps",
        ":vmlinux",
        "//:events",
        "//external_libs/include:stdarg",
        "//sources/common:defines",
        "@libbpf",
    ],
)

bpf_program(
    name = "maps_bpf",
    src = "maps.c",
    core = False,
    deps = [
        ":maps",
        ":vmlinux",
        "//:events",
        "//external_libs/include:stdarg",
        "//sources/common:defines",
        "@libbpf",
    ],
)

pkg_tar(
    name = "sources_tar",
    srcs = [
        ":h2_bpf_core",
        ":maps_core",
        ":openssl_core",
        ":tcp_bpf_core",
        ":tcp_bpf_kprobe_core",
    ],
    extension = "tar.gz",
)

cc_library(
    name = "sources",
    srcs = [":sources_obj"],
    linkstatic = True,
    alwayslink = True,
)

genrule(
    name = "sources_obj",
    srcs = [":sources_tar"],
    outs = ["sources.o"],
    cmd = "cp $(locations :sources_tar) sources.tar.gz && ld -r -b binary sources.tar.gz -m elf_x86_64 -o $@ && rm ./sources.tar.gz",
)
