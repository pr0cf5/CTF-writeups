#!/bin/sh
git clone https://github.com/qemu/qemu.git qemu-git
cd qemu-git/
git checkout -b new_branch 17e1e49814096a3daaa8e5a73acd56a0f30bdc18
patch -p1 < ../qemu.patch
