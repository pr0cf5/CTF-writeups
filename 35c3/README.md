For the 35C3 CTF I solved the challenge 'collection' (pwn/easy)

Although the vulnerability was very easy, it was difficult to find. There were a few reasons for this.

First, it required some knowledge about the Python-C-API.
Second, there was another working vulnerability that discouraged me to look for the easy one. (zero refcount double free) Later by other teams' writeups I realized that the intended one was by using zero refcount but during the CTF I thought this was the result of lazy coding and didn't consider it an intended vulnerability.

Simply the vulnerability is due to the misuse of type_handlers. Type_handler is a structure used to store the types within a collection. If an object is an int, the collection object stores it as a C Int instead of an object. If an int entry is misunderstood as a list or dictionary entry, we can access arbitrary, user controlled pointers which is an extremely powerful primitive.

To understand the vulnerability we must know a few structs defined. After reverse engineering the `Collection.cpython-36m-x86_64-linux-gnu.so` file containing the Collection module, I could know who it works.

The main structure used is the Collection structure. 

struct Collection{
	size_t ob_refcnt;
	PyTypeObject* type;
	type_handler* handler;
}

refcnt is a variable used for garbage collection. Although it was irrevelevant to the solution, there was a bug with refcnt.

struct type_handler{
	list* list;
	size_t refcnt;
}

refcnt has no importance, since it doesn't affect control flow.

struct list{
	node* head;
	node* tail;
	int size;
}

The list struct is allocated using malloc(8), so I thought this was a heap overflow vulnerability but it wasn't. Due to heap allignment only the prev_size of the next chunk was overwritten and I couldn't find a way to exploit this.

struct node{
	record* rec;
	node* next;
}

struct record{
	char* name;
	int type;
}

The Collection module provides a Collection() class which is like a container. The __init__ method takes a dictionary whose keys must be all strings and properties must be one of the following: list, dictionary, python int (long).

Each Collection() has a type_handler, which is used to list what types it contains. type_handler has a list where each node contains information (name, type)

Now, the vulnerability lies in the fact that type_handler is cached and can be used by other Collections if the types are equal. What do you mean by types are equal? It is defined in a function called IsListEqual, and a new type handler is generated only if there is no matching cached type handler. When judging if a type_handler can be used for a Collection, the order of the objects do not matter. However when using the get() method to take out objects it matters, because based on what type an object is the extraction method differs. If we can make an object take a type_handler that is different from its types we can cause unexpected behavior to occur.

Below is the PoC. Let's think about how it's supposed to work.

def arbitrary_read(addr,start,end):
	fakestruct = p64(0xff)+p64(0x9ce7e0)+p64(0x200)+p64(0x201)+p64(addr)*2
	structaddr = id(fakestruct) + 0x48
	#print("[*] target: 0x%x"%addr)
	c1 = Collection.Collection({"a":[],"a\x00":structaddr})
	c2 = Collection.Collection({"a":structaddr,"a\x00":[]})#INT->LIST
	x = c2.get("a")#GET ARBITRARY ADDRESS AS AN OBJECT
	return x[start:end]

def arbitrary_write(addr,offset,ch):
	fakestruct = p64(0xff)+p64(0x9ce7e0)+p64(0x200)+p64(0x201)+p64(addr)*2
	structaddr = id(fakestruct) + 0x48
	#print("[*] target: 0x%x"%addr)
	c1 = Collection.Collection({"a":[],"a\x00":structaddr})
	c2 = Collection.Collection({"a":structaddr,"a\x00":[]})#INT->LIST
	x = c2.get("a")#GET ARBITRARY ADDRESS AS AN OBJECT
	x[offset]=ch

using the collection module we could obtain arbitrary RW.

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

All PyLong objects are stored in C unsigned long form instead of the pointer to the PyObject struct. If we can get a PyLong entry to have a type other than 1, we can make the get() method return an arbitrary pointer. We can do this by creating a type_handler containing a int entry and a list entry. If we switch the order of them and re-create a Collection object it will use the same type_handler but using get() to take out the list will result in returning the value of the int as a pointer. We can get a full arbitrary RW by using bytearrays. There is a member in the bytearray struct that holds its buffer, and by forging a value for that member we can get arbitrary RW.

Now that we have an arbitrary RW primitive, what can we do?
The flag is located in fd 1023 and we only have readv, mmap, and write to load the contents and show it. However I decided to use readv and write because mmap had special constraints to it via seccomp. We cannot use a one_gadget because execve is forbidden. We need a ROP to call all those functions with carefully set arguments. How to we do ROP when there is no stack overflow? We pivot the stack to the heap.

At first I created a ROP chain that works only on the debugger. After adjusting a few offsets I succeeded to read the flag in the local environment. However the exploit failed on the local environment and I decided to write an exploit that always works.

My plan is to defeat ASLR using abitrary read. I used the struct link_map structure located at .got.plt+0x8, which is a structure used to map all the shared objects. Using this I decided to find the `Collection.cpython-36m-x86_64-linux-gnu.so`'s base address.

** one note: All libraries are mmaped adjacent to each other but there were other shared libraries (such as libpthread) linked as well. Therefore the offset could be different in the local and remote environment since libpthread and other libraries' size would be different.

struct link_map{
  ElfW(Addr) l_addr;
  char *l_name;
  ElfW(Dyn) *l_ld;
  struct link_map *l_next,*l_prev;
}

First we read the struct link_map at the static location 0x9B3008, and iterate through the linked list until we get `Collection.cpython-36m-x86_64-linux-gnu.so`. Now we can use gadgets in libc.so.6 and `Collection.cpython-36m-x86_64-linux-gnu.so`.

The reason I tried to use gadgets in `Collection.cpython-36m-x86_64-linux-gnu.so` is because triggering code in `Collection.cpython-36m-x86_64-linux-gnu.so` is much controllable compared to the one in python3.6 for many reasons. First, we do not know if some automatic routine might reuse overwritten GOT values. Also, we do not fully understand how python internals work but we fully understood the functionalities of Colleciton.so. 

First, we need FULL-register control and we can acheive that by arguments passed by registers. The most easiest one was the PyLong_FromLong and its RDI register is user-controlled. I also found this code segment:

1db2: 48 89 fd              mov    %rdi,%rbp
1db5: 89 f3                 mov    %esi,%ebx
1db7: bf 10 00 00 00        mov    $0x10,%edi
1dbc: 48 83 ec 08           sub    $0x8,%rsp
1dc0: e8 db f4 ff ff        callq  12a0 <malloc@plt>

Now if we change malloc_got to a leave; ret gadget we get to control the stack frame, and perform a ROP. Let's summarize the primitives again:

(0) Create a string object with the ROP chain. By using id() we can get the exact address of the ROP chain and save it into the variable fake_stack_addr. (the real address of the string was at an address a bit higher than the PyObject address.)
(1) Create a collection object like the following: Collection.Collection({"abcd":fake_stack_addr})
(2) Get the base address of `Collection.cpython-36m-x86_64-linux-gnu.so` (let's call this CLIB)
(3) Overwrite PyLong_FromLong GOT to CLIB + 0x1db2
(4) Overwrite malloc GOT to a leave;ret gadget
(5) Trigger the ROP using get("abcd")

Now we get RCE via ROP. The ROP chain building part is trivial (we have so many gadgets to use!) so I'll skip the explanation of it. Exploit details can be found in exploit.py
