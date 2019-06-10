import os

f = open("leaking_sand","rb")
data = bytearray(f.read())
data[0x77B:0x77B+5] = bytearray([0x90]*5)
f.close()

f = open("patched","wb")
f.write(data)
f.close()

os.system("chmod +x patched")
