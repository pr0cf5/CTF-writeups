# TWCTF - 2019
I solved three easy-middle level pwnables in TWCTF. Last year, I could only solve 1 warmup pwnable challenge, but this year I did better than that, which is kinda nice.

## Asterisk-Alloc
I am curious why the challenge name is asterisk alloc. But the challenge itself is based on a very famous and well known technique documented very well [here](https://znqt.github.io/hitcon2018-babytcache/). The basic idea is to leak information by partially overwriting fields of `_IO_2_1_stdout` in a wise manner.

The twist in this challenge is that you can't use malloc often. Also, calloc does not use tcache because it only calls `_int_malloc` which does not use tcache. To use malloc as much as we want, we use realloc. If realloc gets a NULL as the first argument, it will call `__libc_malloc`. If we pass a ridiculous number, such as -1 to the second argument of realloc, it will fail and return NULL. Using these two facts, we can call malloc freely.

```python
def malloc(data,size):
	realloc("",2**64-1)
	realloc(data,size)
```

Now the exploit is not hard. The basic idea is to make a tcache bin go into an unsorted bin list and tcache bin list at the same time. This makes the tcache fd become a libc address, and partially overwrite it to get `_IO_2_1_stdout` allocated via tcache poisoning. Afterwards, leak libc address and get arbitrary write and rule the world.

## karte
This is also based on a famous heap exploitation technique. The vulnerability is very straightforward: a use after free, but only one time.

There is a global structure called karte list and a int64 variable called lock. The two are allocated contiguously. If we can overwrite them, we can get an infinite number of arbitrary write, which is more than enough to get a shell.

So, we use a combination of **fastbin dup into .data** and **unsorted bin attack**. First, we use the unsorted bin attack to place a libc address in the middle of the .data section. If we misalign that data by 5, it can be considered as a valid fastbin chunk metadata (with size 0x7F). using fastbin dup, we can get that region allocated, which leads us to overwriting .karte section and overwriting karte objects and the lock variable. Now we just need to enjoy our arbitrary write.

Since there are no leaks, I changed atoi@got to printf and overwrote free@got to system. 

## multiheap
There can be many solutions for this. I looked at the author's write-up and found out that it is related to a class of vulnerability called wild-copy, which is the event where memcpy's third argument goes crazy and overflows a ton of data, which is triggered to RCE before memcpy segfaults.

I also considered this as well, but found a much powerful bug: a race condition. If we copy from one note to another while deleting the dst note, we get a use after free. A use after free in tcache malloc is equivalent to arbitrary write.

Since all addresses are randomized, we first leak a libc address. This can be done with the vulnerability where the heap is uninitialized, so free'ing a 0x500 chunk and getting it back will leak a libc address.

Now using the use after free, we get free hook allocated and get a shell.

To make the race work out successfully, my payload contains a line where we send 2 commands at once to the server. The sleep time is only 1 microsecond, so this was necessary.

```python
def copyAndFree(dst, src, copylen, yn):
	p.send("5\n{}\n{}\n{}\ny\n2\n{}\n".format(src,dst,copylen,dst))
```

