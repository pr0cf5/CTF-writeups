# Secstore
Secstore was a kernel exploit challenge. I will skip the overall structure of this challenge, and go right to the solution.

# Bugs
There are two bugs.
(1) Race condition on `items` buffer. The root cause of this is because `items` is a pointe created via `vmap`, and therefore it can be accessed in userspace via the corresponding user page. At first I wrote a working exploit using this but found the second bug much more reliable and clean. 
(2) `items` buffer can be overwritten by DMA read operation, which causes all kernel checks to be bypassed.
To explain a bit more, look at the following code:

```c
// trigger payload
items[0].src = OFFSET_DATA1;
items[0].dst = (uint64_t)items;
items[0].size = sizeof(items[0]) * 2;
// dummy entry to be overwritten
items[1].src = 0x0;
items[1].dst = (uint64_t)items;
items[1].size = 0x10;
read(device_fd, items, sizeof(items[0]) * 2);
```

The first entry's `dst` is `items`. Since the addresses are pinned, meaning that they have a fixed physical address, `items` and `items[0].dst` end up having the same physical address. Therefore when processing the first entry in the hardware, the first and second entries in `items` are overwritten with whatever data is in DMA `OFFSET_DATA_1`. Therefore we can craft an arbitrary entry and get arbitrary read/write in the kernel.

# Exploitation
There are many strategies for exploitation. Since we can overwrite code in functions, we can overwrite `open` to shellcode and get root. Also, I noticed that `current_task` has a very low entropy, and can be bruteforce-searched with out arbitrary read primitive very easily.  However, I used the following strategy.

(1) Overwrite `open` so that it returns the `current_task`. The `current_task` is stored in a special register, and the ARM assembly that does that is below. We can copy the contents of `return_task` to `open`.
```c
uint64_t return_task() {
    uint64_t task_struct;
    void (*fptr)();
	asm volatile ("mrs %0, sp_el0" : "=r" (task_struct));
    return task_struct;
}
```
(2) Overwrite `fops->lseek` to `open`. 
(3) Call `lseek` on the device and get the address of `current_task`. 
(4) Using the arbitrary read/write, locate `cred` and overwrite it to 0. 

Then we get root.
