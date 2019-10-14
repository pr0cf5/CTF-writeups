# HITCON CTF 2019

I solved lazyhouse, one_punch and trick or treat. I couldn't solve the hard challenges that involved windows or kernel exploitation. This year's linux heap challenges were less spicier than last year (`baby tcache`?) which was a relief.

## Lazyhouse

Explaning the entire exploit is way too coplicated and unnecessary. I'll just talk about the core exploit concept.

```
1. calloc does not use from tcache. In this binary we can only call malloc once. We need to use this for an aribtrary write.
2. There is seccomp enabled, so we need to write an open-read-write exploit. We can't use an easy solution like one_gadget.
3. We cannot use fastbin attack. We can only malloc chunks with sizes >= 0x90
```

The exploit primitive is a heap buffer overflow, but due to these constraints exploitation is not easy.

So, I thought about corrupting the `tcache_perthread_struct` located at heap base + 0x10.

```c
typedef struct tcache_perthread_struct

{

  char counts[TCACHE_MAX_BINS];

  tcache_entry *entries[TCACHE_MAX_BINS];

} tcache_perthread_struct;
```

If we do the actions below, the tcache structure becomes somewhat familiar.

```
1. free 0x3a0 chunks 7 times => tcache->counts[tc_idx(0x3a0)] = 7
2. free 0x390 chunks 1 time => tcache->counts[tc_idx(0x390)] = 1
3. free a 0x20 and 0x30 chunk
```

```
0x7f8a48e08000:	0x0000000000000000	0x0000000000000251
0x7f8a48e08010:	0x0000000000000101	0x0000000000000000
0x7f8a48e08020:	0x0000000000000000	0x0000000000000000
0x7f8a48e08030:	0x0000000000000000	0x0000000000000000
0x7f8a48e08040:	0x0000000000000000	0x0000000000000701
0x7f8a48e08050:	0x00007f8a48e08410	0x00007f8a48e084a0
```

The structure at 0x7f8a48e08040 looks very much like a freed smallbin with a size of 0x700. If we can successfully consolidate a chunk with it we can get it back, giving us full control of the tcache structure. 

In consolidation, there are some checks (the unlink check, the prev size vs size check) but with care, they can be bypassed easily.

After getting tcache, we get `__free_hook` allocated by buying a super house. Changing `__free_hook` to system is useless, because `execve` is unavailable due to seccomp. So I change `__free_hook` to `printf` so we can use a heap format string bug as much as we want.

By using the heap format string bug, we get arbitrary write and execute arbitrary shellcode via a mprotect stager rop. This gives us the flag.

## Trick or Treat
We can two arbitrary writes and a heap leak. We can leak libc address by providing a large size to malloc and making it return an mmmap'ed chunk. 
First, I overwrote `__free_hook` with system in the hope that scanf will free any internal buffers and those buffers can be controlled by us. However, I realized that our input is only put into the buffer when it is a valid hex number.

So, me and my teammates tried a lot of fun things with it, such as `df`, `bc`, ... etc. All of them were useless. Then someone told us there is also `ed`, the builtin editor. I searched the man page for `ed` and it said

```
!command: Executes command via sh(1). If the first character of command is ‘!’, then it is replaced by text of the previous ‘!command’. ed does not process command for backslash (\) escapes. However, an unescaped ‘%’ is replaced by the default filename. When the shell returns from execution, a ‘!’ is printed to the standard output. The current line is unchanged.
```

I guess that's why this challenge was a `pwn, misc`.

## One punch
I used the same technique used for lazyhouse, i'll skip this part.

