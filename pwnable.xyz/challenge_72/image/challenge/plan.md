# Userland Exploit
There is a .bss overflow when adding the last note. The last note's content overwrites note 0's data structure, which enables use to freely execute any syscalls, with 3 parameter control. (RDI, RSI, RDX) By calling write(1,0x4100000,0xFF) we get the flag.

# Kernel Exploit
==========0==========
   0:   48 c7 c0 ff ff ff ff    mov    rax,0xffffffffffffffff
   7:   48 83 ff 00             cmp    rdi,0x0
   b:   75 0f                   jne    0x1c
   d:   48 89 d1                mov    rcx,rdx
  10:   48 89 c8                mov    rax,rcx
  13:   48 89 f7                mov    rdi,rsi
  16:   66 ba f8 03             mov    dx,0x3f8
  1a:   f3 6c                   rep ins BYTE PTR es:[rdi],dx
  1c:   cf                      iret
==========1==========
   0:   48 c7 c0 ff ff ff ff    mov    rax,0xffffffffffffffff
   7:   48 83 ff 01             cmp    rdi,0x1
   b:   75 1b                   jne    0x28
   d:   49 bd 00 00 00 00 00    movabs r13,0x800000000000
  14:   80 00 00 
  17:   49 39 f5                cmp    r13,rsi
  1a:   76 0c                   jbe    0x28
  1c:   66 89 d1                mov    cx,dx
  1f:   48 89 c8                mov    rax,rcx
  22:   66 ba f8 03             mov    dx,0x3f8
  26:   f3 6e                   rep outs dx,BYTE PTR ds:[rsi]
  28:   cf                      iret

In the write syscall there is a boundary check for RSI but in the read syscall there isn't one. Also we can use mprotect to create RWX segments. First we turn the kernel page to RWX and overwrite one of the syscall handlers. (I used syscall handler for RAX=2 which was located at 0xffffffff81000106). Now we have an arbitrary code execution primitive at the kernel level. 

There is a little trick for doing mprotect, due to the fact that mprotect's syscall number is 10, which is a line break. Getting over this is trivial so I'll skip the explanation.

# Hypervisor Exploit

We have RCE at kernel level. There is a critical vulnerability at the interrupt handler where the hypervisor evals() user input. Easy as pie.