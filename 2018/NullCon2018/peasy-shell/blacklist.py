from pwn import *

blacklist = []
whitelist = []

for x in range(256):
	p = process("./gg",alarm=1)
	p.send(chr(x))
	data = p.recvall()
	if("Epic Fail!" in data):
		blacklist.append(x)
	else:
		whitelist.append(x)
	p.close()

print("="*20+"WHITELIST"+"="*20)
for x in whitelist:
	print chr(x),