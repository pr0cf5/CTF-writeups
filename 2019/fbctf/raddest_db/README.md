# Raddest DB

There are two bugs we used

## Type confusion
When a (key,value) is added to a db, the db checks if there exists a value with that key. If this is true, the db only changes the `value` field of the object and leaves the `vtable` field initialized. This leads to a type confusion bugs, giving us 3 primitvies:

```
1. Type confusion from `string`->`int`: consider any string pointer as an int, giving us leaks
2. Type confusion from `float`->`string`: consider any address as a string, which gives use an arbitrary read primitive
```

With these two powerful infoleak bugs, we can get the libc base as well as the heap base.

## Fakeobj???
We found a bug that wasn't found via analysis. It occurs if we do the following (One of my teammates found it and I still don't know how it was triggered, but we can make some guesses that it is a UAF)


cmd("create db") 
cmd("store db int 1 1337")
cmd("getter db 1 2")
p.sendline("echo {}".format("A"*0x10+p64(fakeobj_addr).strip("\x00")))
p.sendline("empty")

cmd("print db")


I made some speculations about how this happened: 
1. Each entry (key,value) is stored as a 0x18 sized structure, which contains the pointer to the object. So in code it is like this:
```
struct entry {
	char unknown[0x10];
	struct object *obj;
}
```

```
struct object {
	funcptr_t *vtable;
	union value {
		unsigned long int_form;
		char *string_form;
		double float_form;
	}
}
```

When we empty a db, the entry structure is free'd and the BUF in echo{BUF} takes that chunk if BUF is of appropriate size. Afterwards the reference is not removed and we have a `fakeobj` primitive, which gives us a single RIP control with no arguments controlled.
In code, it is like this: `this->vtable->func1(this, aux);`

We have control to the entire `this` structure, so we can control `func1`. I changed `func1` to all one shot gadgets (found using david942j's `one_gadget`) but none of them popped a shell. 

I decided to expand this primitive to an arbitrary write primitive by changing `func1` to `gets`.

Before triggering the vtable function we free the chunk right under where the `this` object is located, turning it into a freed, size 0x20 tcache bin. Overflowing `this` enables us to overwrite a tcache bin, which gives use arbitrary allocation. So, I changed the `fd` field of the next tcache chunk entry to `__free_hook` and got `__free_hook` allocated and wrote `system` to it.

I tried some commands that would trigger `free('/bin.sh;'`. (The way was to enter /bin/sh;[LOTS OF SPACES] as the command because when the string is extended to some length its original buffer is freed (property of c++'s std::vector)


