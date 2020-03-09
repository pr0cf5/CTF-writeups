#!/bin/sh
cd exploit
./compile.sh
cd ..
cp ./exploit/runme ./initramfs/tmp
cd initramfs
mkdir -p sys dev tmp proc run
find . | cpio -H newc --owner root -o > ../rootfs.cpio
cd ..
