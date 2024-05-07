.code

GetBase proc 

		xor rax, rax
		xor r11, r11
		mov rax, 12
		shl rax, 3
		mov rax, qword ptr gs:[rax + 0]
		mov r11, rax
		mov r11, [r11 + 10h]
		mov qword ptr [rcx], r11
		mov rax, [rax + 18h]
		mov rsi, [rax + 20h]
		mov rsi, qword ptr [rsi + 8h]
		lodsq
		xchg rax, rsi
		lodsq
		mov rax, [rax + 60h]
		sub rax, 16C280h       
		ret
		
GetBase endp

MoveSyscallAddress proc
		xor r11, r11
		mov r11, rcx
		ret
MoveSyscallAddress endp

end