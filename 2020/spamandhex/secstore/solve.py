#!/usr/bin/python3
from pwn import *
from subprocess import check_output

if __name__ == "__main__":
    p = remote("35.246.85.118", 1337)
    p.recvuntil("Solve PoW with: ")
    hashcash_cmd = p.recvline().strip()
    log.info("hashcash_cmd: %s"%hashcash_cmd)
    hashcash_sol = check_output(hashcash_cmd.split(b" ")).replace(b"\n", b"")
    log.info("hashcash_sol: %s"%hashcash_sol)
    p.sendline(hashcash_sol)

    with open("exploit/exploit", "rb") as f:
        data = f.read()
    assert(len(data) < 10 * 1024 * 1024)
    p.sendlineafter("Size of payload in bytes: ", str(len(data)))
    for i in range(0, len(data), 1000):
        if i + 1000 > len(data):
            p.send(data[i:])
        else:
            p.send(data[i:i+1000])
        log.info("sent %d/%d bytes"%(i + 1000, len(data)))
    p.interactive()