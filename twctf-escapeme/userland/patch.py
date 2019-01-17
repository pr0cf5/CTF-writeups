from pwn import *

def stringfy(arr):
	return "".join(map(chr,arr))

context.os = 'linux'
context.arch = 'amd64'

offset = 0x337 
dis = '''
mov rdi,0x100
mov r15,0x4007C7
call r15
push rax
mov rax,1
mov rdi,1
mov rsi,rsp
mov rdx,0x8
syscall
'''

code = asm(dis)
data = bytearray(open("patchme","r").read())
data[offset:offset+len(code)] = bytearray(code)

fp = open("patched","w")
fp.write(stringfy(data))
fp.close()
