# Babyheap

The purpose of the challenge was to exploit a single byte overflow in ptmalloc, libc-2.29 which is a super recent version. 

# Setting up a debugging environment

As far as I know there are only a few linux distros using libc-2.29. Therefore, `LD_PRELOAD=./libc.so.6 ./babyheap` would've caused it to crash because the `ld` version and `libc` version do not match at all. This can be resolved by downloading a `libc6` package for version 2.29 from ubuntu and extracting `ld-2.29.so` from it. Afterwards we can execute ./babyheap with the libc provided by the challenge author by executing `LD_PRELOAD=./libc.so.6 ./ld-2.29.so ./babyheap`. There are some drawbacks if you use this. One of them is that the heap and code segment (under PIE) is mapped adjacent to the LIBC segments which is not realistic and makes me feel awkward. (heap in `0x7f**********` is just so awkward!!) Other than that there are no problems. You can attach to gdb like any other process, read memory maps from `/proc/self/maps` and etc.

# Vuln

The vulnerability is straightforward and easy: a single byte overflow. It's a very powerful primitive that is not so realistic but who cares? `make note` style challenges are never realistic anyway
```
read(0, &ch, 1);

while ( ch != 10 && ch )
{
	content[i] = buf;
	read(0, &ch, 1);
	if ( i == length )
	  return 0;
	++i;
}
```

# When life gives you lemons

There are a few factors that made the exploitation hard.

1. You cannot input multiple pointers into the buffer because input is terminated at NULL alongwith newline. (Making multiple pointers is really important in glibc exploit because many times you need to make a fake malloc_chunk structure which as size, FD and BK which are already 3 pointer equivalents.)

2. You can only create chunks with size 0x178 and 0xF8 but this is not that bad because chunks with size `0x10*N+8` can be used for overwriting the next chunksize.

3. The buffer is `bzero`'ed before being free'd.

1 and 3 really makes it hard to create valid fake structures on the heap but this can be bypassed with a simple gimmick. For every creation of a creation of a chunk you can write one more byte than the length you gave. However the memset(0) is done only up to the length you gave. Therefore even after freeing the last byte you provided remains. By using this we can write any sequence of bytes by continuously free'ing and malloc'ing on the same address. (However you can't do this for the first 16 bytes of a chunk because they are altered at free)

```
payload = payload[::-1]
for i in range(0x10,1,-1):
	ch = payload[-i]
	if ch == "\x00" or ch == "\n":
		malloc(i+0xF7,"A"*(i+0xF7)+payload[-i]) #1
		free(1)
	else:
		malloc(i+0xF7,"A"*(i+0xF7)+payload[-i]+"\n") #1
		free(1)
```

Here's the code that did the work. It leaves the payload byte by byte in the heap.

# How to exploit one-byte overflow

At first I thought about exploiting using the famous `House of Einherjar` or `Poison Null Byte`. However a single byte overflow is much powerful compared to a single null byte overflow and I decided to take advantage of it. You can change a one-byte overflow primitive into a heap overflow primitive by following the steps.

```
(1) Create 4 0xF8 size chunks. (Call them 0, 1, 2 and 3)
(2) Overwrite the least significant byte of the `size` field of chunk1 by overflowing chunk0, and set its size to 0x181 (it should've been originally 0x101)
(3) Free chunk 1, and it will be inserted into the size 0x181 tcache bins.
(4) Free chunk2, which will turn into a free chunk structure.
(5) Allocate a 0x178 chunk and the address at what was chunk1 will be allocated. Now you can overflow the first 0x80 bytes of chunk2 by writing at chunk1.
(6) Overwrite the FD of chunk2 to the address you want to get arbitrary write to (The tcache area is a good target)
(7) Enjoy the arbitrary write
```

Leaks are pretty hard to explain so i'll just skip it. Heap leaks are pretty straightforward and libc leaks require reading the FD and BK of unsorted bins.

# Overall Opinions

ptmalloc exploit challenges are quite obsolete and nothing new is there anymore. It's just a matter of bypassing barriers and the core idea is always the same. I hope to not see these kinds of challenges in the future.

