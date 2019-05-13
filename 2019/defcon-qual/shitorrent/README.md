# Shitorrent

As the name suggests the binary is a client that connects to TORADMINs and TORCLIENTS and sends packet between them. The vulnerability was found by a teammate and it was something that I had never seen before, but was quite feasible in real-world.

# Vuln

```
fd_set fds;
rfds = &fds;
lastfd = 2;
```

`rfds` points to a fd_set structure in the stack, which is a 128bit bitmap object. When a connection to an admin node is made the corresponding bit in the bitmap is turned on. To elaborate, if a socket with fd 5 connects to an admin node the 5th bit of fds is turned on. This is done in the following code.

```
char *hello = "SHITorrent HELO\n";
send(sock , hello , strlen(hello) , 0 );

valread = read( sock , buffer, 1024);
if (strncmp("TORADMIN", buffer, strlen("TORADMIN"))) {
	listeners.push_back(sock);
	printf("added listener node %d\n", sock);
} else {
	admins.push_back(sock);
	FD_SET(sock, rfds);
	printf("added sending node %d\n", sock);
}
```

An admin server sends the TORADMIN magic on connection. All others are considered as clients. The `FD_SET(sock,rfds)` sets the `sock`th bit of rfds to 1. The vulnerability lies here: `sock` may be bigger than 1024, resulting in bit overflows, which is equivalent to a stack overflow primitive. The author set an rlimit so that we can only open up to 65536 file descriptors, which is quite enough to create a ROP chain.


# Initial Exploit

My initial exploit opens two servers on my IP address, one imitating a client node and one imitating an admin node. There is a stack canary which can be easily bypassed by using client nodes instead of admin nodes so that that part of the stack will be intact. After passing the stack canary we first the RIP with bits of 1 (which will make it 0xFFFF...FFF). Then we turn off the bits appropriately to forge whatever RIP we like. This can be done with the following code.

```
for i in range(len(ROP)*8):
		add_node(ah,ap)

offset = 0x88*8+0x10*8

for i in range(len(ROP)*8):
	if not bitat(ROP,i):
		remove_node(i+offset)
```

The ROPping part is very trivial. I used an mprotect-read chain to set 0x400000 to RWX, write shellcode to it and jump to 0x400000. This successfully gave me a shell on my local machine but it did not work on the remote machine. The problem was that my exploit timed out. We needed to find ways to shorten time consumption.

# Some tricks

The first trick that my teammate suggested was to use 127.0.0.1 4747 which is the service binded to localhost. Connecting to this server was much faster than connecting to an external server and shortened the time a bit, but this was not enough.

So one of our teammates generously opened up an Amazon AWS SSH session for me and I ran the exploit. It became very very fast but still not enough. This time the ROP chain was too long and I decided to shorten it to a reasonable length. I found out that right at the `ret` instruction of `main` function `rdi` is set to 0 and `rsi` is set to a stack poiter above the current stack pointer. Therefore I devised the following ROP chain to read a longer ROP chain into the stack. 

`loader = p64(pop_rdx)+p64(218+len(ROP))+p64(read)+p64(0)`

Afterwards we can send our 'real' ROP and shellcode.

# Some opinions

The exploit primitive of this challenge was very unique and quite reasonable. I guess this kind of vulnerability is pretty feasible in binaries using the `fd_set` structure. However, the wrapper timeout ruined the essence and turned it into an unfair challenge. I think this was the easiest pwnable of all challenges in DEFCON 27 quals, but the solves were quite low because of this. People far from the States probably suffered from the timeout issue and I heard that some teams got a functioning local exploit but couldn't get the flag. I think the authors should be pretty generous about timeouts and open many servers so that the remote service works properly. Other than that it was a pretty good, interesting and informative challenge.




