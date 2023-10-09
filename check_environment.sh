#!/bin/bash

# Check if the necessary kernel modules are loaded
if [[ ! -d "/sys/fs/bpf" ]]; then
    echo "Kernel not compiled with eBPF support"
    exit 1
fi
echo "Kernel compiled with eBPF support"

#Check if the vmlinux exists for CO-RE
if [[ -e "/sys/kernel/btf/vmlinux" ]]; then
    echo "Kernel compiled with vmlinux support"
    echo "You can use ebpf-transport-monitoring binary"
    exit 0
fi

echo "Kernel not compiled with vmlinux support"

# Check if release information is available
if [ ! -r /etc/os-release ] ; then
  echo "Could not find release file at /etc/os-relase" 
  exit 1
fi

# Loading ID and VERSION_ID varaibles
. /etc/os-release

KERNEL=$(uname -r)
ARCH=$(uname -m)

#Checking if reduced btf information is available in ebpf-transport-monitoring
URL="https://github.com/lasradoVinod/btfhub-archive/raw/main/$ID/$VERSION_ID/$ARCH/$KERNEL.btf.tar.xz"
HTTPCODE=`curl -o /dev/null -s -w "%{http_code}\n" $URL`

echo Checking $URL Received $HTTPCODE
if [[ $HTTPCODE -ge 400 ]]; then
  echo "You will need to compile ebpf code on host."
  exit 1
else
  echo "BTF information avaiable with ebpf-transport-monitoring binary"
  echo "You can use ebpf-transport-monitoring binary"
  exit 0
fi 
