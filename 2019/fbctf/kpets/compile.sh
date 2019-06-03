#!/bin/sh
gcc -static -pthread -o exploit exploit.c
strip exploit

