#!/bin/sh
mkdir -p initramfs
cd initramfs
gzip -cd ../initramfs.cpio.gz | cpio -imd --quiet
