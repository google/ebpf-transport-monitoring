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

"""The build rules for eBPF programs and skeleton headers."""

def get_basename(path):
    """This function gets the name of the file

    Args:
        path: path of file of which we need to extract file name

    Returns:
        The stripped file name.
    """
    if not path[-2:] == ".h":
        return path
    loc = path.rfind("/")
    if loc == -1:
        return "."
    else:
        return path[:loc]

def get_include_files(ctx):
    """This function goes through the dependencies and return a list of paths to be imported

    Args:
        ctx: bazel ctx as passed by the rule

    Returns:
        List of paths and files to be included
    """
    files = []
    include_paths = []
    for dep in ctx.attr.deps:
        for header in dep[CcInfo].compilation_context.headers.to_list():
            path = get_basename(header.path)
            if not path in include_paths:
                include_paths.append(path)
            files.append(header)
    return include_paths, files

def _bpf_program_impl(ctx):
    include_path, files = get_include_files(ctx)
    src = ctx.file.src.path
    out_file = ctx.actions.declare_file("%s.o" % ctx.attr.name)

    warnings = " -Wunused -Wall -Wno-frame-address \
	       -Wno-unused-value -Wno-unknown-warning-option \
	       -Wno-pragma-once-outside-header -Wno-pointer-sign \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-deprecated-declarations \
		-Wno-compare-distinct-pointer-types \
		-Wno-address-of-packed-member \
		-fno-stack-protector \
		-fno-jump-tables "

    common_cmd = "export UNAME_M=`uname -m` && export UNAME_R=`uname -r` &&" + \
                 " if [ $UNAME_M = x86_64 ]; then ARCH=x86_64; LINUX_ARCH=x86; fi &&" + \
                 " if [ $UNAME_M = aarch64 ]; then ARCH=arm64; LINUX_ARCH=arm64; fi &&" + \
                 " KERN_BUILD_PATH=/lib/modules/$UNAME_R/build &&" + \
                 " KERN_SRC_PATH=$KERN_BUILD_PATH &&" + \
                 " if [ -d /lib/modules/$UNAME_R/source ] ; then KERN_SRC_PATH=/lib/modules/$UNAME_R/source ; fi && "

    includes_str = "-include $KERN_SRC_PATH/include/linux/kconfig.h " + \
                   " -idirafter $KERN_SRC_PATH/include " + \
                   " -idirafter $KERN_BUILD_PATH/include " + \
                   " -idirafter $KERN_SRC_PATH/include/uapi " + \
                   " -idirafter $KERN_BUILD_PATH/include/generated " + \
                   " -idirafter $KERN_BUILD_PATH/include/generated/uapi " + \
                   " -idirafter $KERN_SRC_PATH/arch/$LINUX_ARCH/include " + \
                   " -idirafter $KERN_SRC_PATH/arch/$LINUX_ARCH/include/uapi " + \
                   " -idirafter $KERN_BUILD_PATH/arch/$LINUX_ARCH/include/generated " + \
                   " -idirafter $KERN_BUILD_PATH/arch/$LINUX_ARCH/include/generated/uapi "

    cmd = ""
    if ctx.attr.core:
        cmd = common_cmd + "clang  -g -O2  -target bpf -D__TARGET_ARCH_$LINUX_ARCH {} {} -c {} -DCORE {} -o {} && llvm-strip -g {}".format(
            ("".join([" -I {}".format(i) for i in include_path])),
            " ",
            src,
            ("".join([" -D{}".format(m) for m in ctx.attr.macros])),
            out_file.path,
            out_file.path,
        )
    else:
        compile_cmd = common_cmd + "clang -S  -xc -g -O2 -emit-llvm -fno-asynchronous-unwind-tables -nostdinc -D__TARGET_ARCH_$LINUX_ARCH -D__BPF_TRACING__" + \
                      " -D__KERNEL__ {} {}  -c {} {} {} -o /tmp/temp.s ".format(
                          ("".join([" -I {}".format(i) for i in include_path])),
                          includes_str,
                          src,
                          ("".join([" -D{}".format(m) for m in ctx.attr.macros])),
                          warnings,
                      )

        link_cmd = "&& llc -march=bpf -mcpu=v2 -filetype=obj -o {} /tmp/temp.s".format(out_file.path, out_file.path)
        cmd = compile_cmd + link_cmd

    ctx.actions.run_shell(
        inputs = [ctx.file.src] + files,
        # Output files that must be created by the action.
        outputs = [out_file],
        command = cmd,
    )
    return [DefaultInfo(files = depset([out_file]))]

bpf_program = rule(
    implementation = _bpf_program_impl,
    attrs = {
        "src": attr.label(mandatory = True, allow_single_file = True),
        "deps": attr.label_list(allow_empty = True),
        "core": attr.bool(default = True),
        "macros": attr.string_list(allow_empty = True),
    },
)
