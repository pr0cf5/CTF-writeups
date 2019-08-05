from pwn import *

def hexdump(proc,addr,ele_cnt):
	if ele_cnt%2==1:
		ele_cnt+=1

	num_iters = ele_cnt//2

	data = proc.leak(addr,num_iters*0x10)

	for i in range(num_iters):
		x1 = u64(data[i*0x10:i*0x10+8])
		x2 = u64(data[i*0x10+8:i*0x10+0x10])
		print("0x%x: 0x%016x 0x%016x"%(addr+0x10*i,x1,x2))

def find_overwritable_syms(addr,size,libc_base,syms):

	names = []
	trimmed_size = size & (~7)
	for x in syms:
		if(addr <= libc_base+syms[x] <= trimmed_size + addr):
			names.append(x)

	return names

def get_PIE(proc, idx=0):
	memory_map = open("/proc/{}/maps".format(proc.pid),"rb").readlines()
	return int(memory_map[idx].split("-")[0],16)

def get_fastbin_targets(proc):
	memory_map = open("/proc/{}/maps".format(proc.pid),"rb").readlines()
	libc = ELF("./libc.so.6")
	syms = libc.symbols

	writable = []
	got_libc_base = False

	for x in memory_map:
		if 'libc.so.6' in x:
			l = x.split(" ")
			mem_start = int(l[0].split("-")[0],16)
			mem_end = int(l[0].split("-")[1],16)

			if not got_libc_base:
				LIBC = mem_start
				got_libc_base = True

			prot = l[1]
			if 'rw' in prot:
				writable.append((mem_start,mem_end))

	addrs = []

	for s,e in writable:
		size = e-s
		data = proc.leak(s,size)
		for i in range(size-8):
			if data[i+1:i+8] == "\x00"*7 and data[i]!="\x00":
				addr = i+s
				fastbin_size = ord(data[i])
				overwritable_syms = find_overwritable_syms(addr,fastbin_size,LIBC,syms)
				addrs.append((addr-LIBC,fastbin_size,overwritable_syms))

	return addrs
