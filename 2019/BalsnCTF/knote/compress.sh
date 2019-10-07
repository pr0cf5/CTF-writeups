#!/bin/sh
#cd exploit
#gcc -o exploit -static -Os exploit.c
#strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag exploit
#cd ..
cp ./exploit/exploit ./initramfs/home/note/exploit
cd initramfs
find . | cpio --quiet -H newc -o  | gzip -9 -n > ../initramfs.cpio.gz
cd ..

