from pwn import *

context.os = 'linux'
context.arch = 'amd64'

fp = open("kernel","rb")
data = fp.read()
fp.close()

BASE = 0xFFFFFFFF81000000
syscall_handler = u64(data[0x1d:0x1d+8])

print("[*] syscall handler at: 0x%x"%syscall_handler)

x = syscall_handler - BASE
code = data[x:x+30]
'''
0:   48 8d 1c c5 80 02 00    lea    rbx,[rax*8-0x7efffd80]
7:   81 
8:   ff 24 c5 80 02 00 81    jmp    QWORD PTR [rax*8-0x7efffd80]
'''

x = 2**64-0x7efffd80 - BASE

for i in range(20):
	addr = u64(data[x+8*i:x+8*i+8])
	offset = addr - BASE
	print("="*20+str(i)+"="*20)
	print("addr: 0x%x"%addr)
	idx = offset
	ch = "\x00"
	while ch!="\xcf":
		ch = data[idx]
		idx+=1
	print(disasm(data[offset:idx]))

#syscall number 10 has something special! an interrupt