#!/bin/bash

set -ex

pushd ./mod
make
popd

pushd ./exploit
gcc exploit.c -static -o exploit
popd

./addfile.sh ./mod/dbg.ko
./addfile.sh ./exploit/exp

qemu-system-x86_64 \
    -snapshot \
    -gdb tcp::1234 \
    -enable-kvm \
    -cpu host \
    -smp sockets=1,cores=4,threads=2 \
    -m 4G \
    -kernel ./images/vmlinuz \
    -drive file=./images/bullseye.img,format=raw \
    -append "nokaslr root=/dev/sda rw console=ttyS0 panic=0 quiet net.ifnames=0" \
    -nographic \
    -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
    -net nic,model=virtio \
    -monitor /dev/null
