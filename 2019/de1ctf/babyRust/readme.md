# babyRust

babyRust is a rust pwnable, which has 6 options excluding `exit`.
```
You have a magic box.
1.create
2.show
3.edit
0x520~0x522.magic
4.exit
```

## recon

Doing create or edit asks for 5 input, where 1 of them is a name (string) and the other 4 are numbers. I speculated that since the binary is compiled with rustc, there mustn't be any obvious, ancient bugs like stack/heap buffer overflows. I played around with the options a few times and got a crash immediately.
Also, I did >0x520 and show'ed the output, which was this.
```
S(94159028869952, ,0,0,0)
```
The first large number was definitely a heap pointer, and it could be identified by converting it to hex.
There seems to be a type confusion between int and string pointer.

Also, I used the other two magics (0x521 and 0x522) and the first letter changed every time I did it. It seems that the 'magic's are operations that change the type of some container or structure, but the type system is inconsistent with it.
One other thing interesting that I found out was that only one magic can be used for a specific state (or type). That means the order of using magics (0x520->0x521->0x522->0x520->...) must be the same, always.

## analysis
Analyzing rust binaries are similar to analyzing c++ binaries. All automatically generated routines should be overlooked or speculated. The main routine was in the main::main function, where I could clearly identify what looked like a switch-case in an infloop. As in the menu, there were 3 operations and 3 magics. I took a look at the create option by looking at main::create function/

It is clear that the routine reads 4 numbers and a string. Some more analysis reveals the memory structure of the so called 'magic box'.

```
struct magicBox {
	unsigned long unk;
	struct packedString;
	unsigned long num1;
	unsigned long num2;
	unsigned long num3;
	unsigned long num4;
};

struct packedString {
	char *buf;
	unsigned long length;
};
```

At first some things were not clear but I set a breakpoint on the main::create function's important parts and observed the memory directly. This helped me reverse the routine in a very speedy manner.
The edit option was similar to create, but there were mainly 3 branches. Each branch corresponded to a certain type. So it seems that there are 3 types of magic boxes, and the type confusion between them caused the information leak. Analyzing the edit function revealed that there are three forms of magic boxes, 'boom', 'S' and 'F'. boom is the default type, where 'S' and 'F' are in the following form.

```
struct magicBoxS {
	unsigned long num1;
	unsigned long num2;
	unsigned long num3;
	struct packedString name;
	unsigned long num4;
	unsigned long unk;
};

struct magicBoxF {
	struct packedString name;
	unsigned long num1;
	unsigned long num2;
	unsigned long num3;
	unsigned long num4;
	unsigned long unk;
};
```

This explains why a heap pointer was printed as int after doing magic 0x520. A char * was misidentified as an unsigned long. Then, I thought can I confuse an int to a char *? This would give us arbitrary read? And sure it was.  After some trial and error, I could segfault the program by making it try to access the address 0xdeadbeef. Afterwards, I scanned the heap to cause other leaks, and I found something like this:
F(93874519129536, 17,17,\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x04\x00\x00\x00\x00\x00\x00F(93874519129536, 17,17,create
2.show
3.edit
0x520~0x522.magic
4.exit
243d2000 rw-p 00000000 00:00 0 
7f26243e9000-7f26243ea000 r--p 00027000 08:01 923645                     /lib/x86_64-linux-gnu/ld-2.27.so
7f26243ea000-7f26243eb000 rw-p 00028000 08:01 923645                     /lib/x86_64-linux-gnu/ld-2.27.so
7f26243eb000-7f26243ec000 rw-p 00000000 00:00 0 
7ffce0515000-7ffce0536000 rw-p 00000000 00:00 0                          [stack]
7ffce05a6000-7ffce05a9000 r--p 00000000 00:00 0                          [vvar]
7ffce05a9000-7ffce05ab000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
1 923696                     /lib/x86_64-linux-gnu/libdl-2.27.so
7f26241c0000-7f26241c1000 r--p 00002000 08:01 923696                     /lib/x86_64-linux-gnu/libdl-2.27.so
dl-2.27.so
7f26241c0000-7f26241c1000 r--p 00002000 08:01 923696   ,0)
You have a magic box.

What I see are contents printed to stdout and the contents of the file `/proc/self/maps`. I think I scanned the file read buffer of stdout and `/proc/self/maps`. (The former was probably opened due to an automatic routine in rust, as means to protect memory) Now I have the stack base address and ld-2.27.so's base address, but all the important stuff like **system** and **__free_hook** is in libc.so.6. So, I read the pointer of __libc_malloc from ld-2.27.so's malloc@got, and I got the libc base.

## Getting arbitrary write
I didn't do a full-analaysis of the binary and I couldn't figure out why some operations would cause a crash. I attached gdb to the process and observed the heap, and I found a sign of a double-free in tcache bins (This can be easily done by doing `p *tcache`) in gdb. Then I speculated that, every time I use a 'magic' what used to be the string is `freed`, right? Analyzing the magic further proved this to be true. Every time a magic is executed, the original object goes through the `core::ptr::real_drop_in_place` function, which is the rust equivalent to a c++ destructor call. Therefore, I have an arbitrary `free` primitive, which can be used to create an arbitrary write primitive very easily in tcache malloc. Since I have all leaks, I can overwrite __free_hook to system and execute arbitrary commands. Since the rust binary aborts when something not-sane gets inputed, I made the binary execute `ls -al; cat flag` instead of popping up a shell.

