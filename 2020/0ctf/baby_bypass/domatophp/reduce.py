#!/usr/bin/python3

import sys
import os
import subprocess

def reduce_useless_lines(script, lines):
    out = []
    for i,x in enumerate(script):
        if i in lines:
            continue
        else:
            out.append(x)
    return out

def run_script_with_line_removed(script, line):
    script_to_run = ""
    for i,x in enumerate(script):
        if i == line:
            continue
        else:
            script_to_run += x
    with open("/tmp/temp.php", "w") as f:
        f.write(script_to_run)
    
    cmdline = "php {} 1>/dev/null 2>/dev/null".format("/tmp/temp.php")
    argv = cmdline.split(" ")
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return_code = p.wait()

    if return_code == -11 or return_code == -6:
        return True
    return False
    

if len(sys.argv) != 2:
    print("usage: ./reduce.py <pwn.php>")
    exit(-1)

with open(sys.argv[1], "r") as f:
    script = f.readlines()

print("[*] {} has {} lines".format(sys.argv[1], len(script)))

if not run_script_with_line_removed(script, -1):
    print("{} does not cause php to crash...".format(sys.argv[1]))
    exit(-1)

reduce_successful = True
reduced_script = script[:]
while reduce_successful:
    useless_lines = []
    for i, x in enumerate(reduced_script):
        if ("<?" in x) or ("?>" in x) or (not "try" in x):
            continue
        if run_script_with_line_removed(reduced_script, i):
            useless_lines.append(i)
            print("[*] removing line {} doesn't prevent the crash".format(i))
            break
        else:
            continue
    reduce_successful = len(useless_lines) > 0
    reduced_script = reduce_useless_lines(reduced_script, useless_lines)
    print("[*] removed {} lines".format(len(useless_lines)))

print("[+] reduce done, reduced to {} lines".format(len(reduced_script)))

with open("./reduced.php", "w") as f:
    f.write("".join(reduced_script))
