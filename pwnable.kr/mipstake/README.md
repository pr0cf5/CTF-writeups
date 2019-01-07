# Pwnable.kr: Mipstake

## Summary
I have never done any MIPS binary exploitation/reversing before and mipstake was a good intro challenge to get me into it. Also I learned how to set up debuggng environemnts for MIPS binaries. I got all the information from this document: 
https://gsec.hitb.org/materials/sg2015/whitepapers/Lyon%20Yang%20-%20Advanced%20SOHO%20Router%20Exploitation.pdf

## The vulnerability
In the handle_client function (I don't know what it's named exactly) there is a obvious buffer overflow.

```
void handle_client(int clifd){
	char buf[??]; //0x18
	void *retaddr; //0x4
	my_recv(clifd,buf,0x2000);
}
```

Also, the binary doesn't have any memory protections. We can use ret2shellcode. But before that we have to place shellcode somewhere. First we can write a whole lot to the stack buf we don't know its address. The entire MIPS server is a forkserver. We can bruteforce the stack address, and aid its success rate with a NOP sled. However this is not a gorgeous way of solving this challenge. my_recv forces to get full 0x2000 bytes and therefore each 'cycle' will take a long time. Although its 32bit address space which has low entropy and makes bruteforcing quite reliable and realistic, I thought there would be a better way to do this. My idea is to make a ROP chain that leaks the stack address. After doing this a few times we can check if ASLR is enabled or not. If ASLR is disabled on the system we can trigger the exploit with a single IP control.

```
Arch:     mips-32-big
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

## Debugging
As shown in the document the ideal way to debug our exploit is to setup a GDB server. Since I don't have access to a MIPS device I decided to use qemu-system-mips.

### Preparing QEMU (Ref: https://markuta.com/how-to-build-a-mips-qemu-image-on-debian/)

(1) Install qemu-system-mips, the MIPS emulator. `sudo apt-get install qemu-system-mips`

(2) Download the Debian initial ramdisk for MIPS-Malta, a version of MIPS32: `wget http://ftp.debian.org/debian/dists/stable/main/installer-mips/current/images/malta/netboot/initrd.gz`

(3) Download the Debian kernel image in the following URL: ` http://ftp.debian.org/debian/dists/stable/main/installer-mips/current/images/malta/netboot/` The filename must be something like `vmlinux-4.9.0-8-4kc-malta` with the version numbers different.

(4) Create a qcow 2 image with appropriate size (with desktop features(GUI) 10GB is recommended. Without it 2GB is sufficient): `qemu-img create -f qcow2 hda.img 20G`

(5) Boot the device: `qemu-system-mips -M malta \
  -m 256 -hda hda.img \
  -kernel vmlinux-<version>-malta \
  -initrd initrd.gz \
  -append "console=ttyS0 nokaslr" \
  -nographic`

(6) Install the system. (this will take some time)

(7) If you want to install a desktp environment execute the following instructions:
