#!/bin/sh
cd `dirname $0`
aarch64-linux-gnu-gcc -o exploit -pthread -static exploit.c
