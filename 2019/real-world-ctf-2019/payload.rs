#include <constants.rh>
#include <util.rh>
#include <math.rh>
#include <crctools.rh>
; vim: syntax=fasm

; Test RAR assembly file that just demonstrates the syntax.

_start:
	; Install our message in the output buffer
	mov r3, #0x0
	add r3, #0x1622bff0 ; offset between unrar start and mmap chunk
	add r3, #0x20C018
	mov r4, [r3]
	sub r4, #296208
	mov [r3], r4 ; change free to system
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	mov r3, #0x0
	
	mov [r3+#0], #0x6e69622f
	mov [r3+#4], #0x7361622f
	mov [r3+#8], #0x632d2068
	mov [r3+#12], #0x2f282220
	mov [r3+#16], #0x2f6e6962
	mov [r3+#20], #0x20746163
	mov [r3+#24], #0x616c662f
	mov [r3+#28], #0x202f2067
	mov [r3+#32], #0x31263e32
	mov [r3+#36], #0x203e2029
	mov [r3+#40], #0x7665642f
	mov [r3+#44], #0x7063742f
	mov [r3+#48], #0x322e312f
	mov [r3+#52], #0x352e3535
	mov [r3+#56], #0x33362e34
	mov [r3+#60], #0x3939392f
	mov [r3+#64], #0x2238
	call $_success

_infloop:
	jmp $_infloop

