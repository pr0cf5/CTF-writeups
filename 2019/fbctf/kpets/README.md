There is a TOCTOU bug in the kpets_write function.
The kpets_write function is simply this in pseudocode:
```
size_t kpets_write (struct kpet *user_ptr, size_t length) {

	#1
	copy_from_user(&name_len, &user_ptr.name_len, 4);
	if (name_len  > 0x20) {
		printk("name is too long!");		
	}
	
	...
	
	copy_from_user(&name_len, &user_ptr.name_len, 4);
	#2
	copy_from_user(&pets[idx].name, &user_ptr.name, name_len);
}
```

Because name_len can change from line 1 and line 2, it is insecure. Therefore we have a buffer overflow primitive in the pets[] buffer array. 
After some reversing I realized that if there is a pet type with 0xAA reading from the device gives us the flag.

However when creating a pet (via `kpets_write`) it checks if the type is 0xC2 and denies all other types. We create 2 pet objects, and overflow the one in the lower address and change the type field of the pet at the highest address. You can see how exactly it is done in exploit.c

It is a type of a TOCTOU (https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)bug, which is quite common in the real world.
