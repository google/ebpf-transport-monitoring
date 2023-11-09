
# Build Instructions

* Clone repository 
*  Install bazel from [https://bazel.build/install](https://bazel.build/install)
*  Install dependencies
    a. m4
    b. clang
    c. libssl-dev
    d. libcurl4-openssl-dev 
    e. libarchive-dev
    f. libsqlite3-dev
    g. libmicrohttpd-dev
    h. pkg-config
*  Make sure the paths for clang, llc, and llvm-split.
On installation my machine has clang-11. I used the following to change it to clang. 
```
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 380
sudo update-alternatives --install /usr/bin/llc llc /usr/bin/llc-11 380
sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-11 380
```
* Build
```
cd grpc-gcp-tools/ebpf_transport_monitoring/
bazel build :lightfoot
```
*  For older kernels
```
bazel build //sources/bpf_sources:h2_bpf
bazel build //sources/bpf_sources:tcp_bpf
bazel build //sources/bpf_sources:tcp_bpf_kprobe
```
