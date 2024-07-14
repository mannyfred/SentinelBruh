.code

Oops proc
		
		hlt
		xor rax, rax
		ret

Oops endp

Patch proc

		xor rax, rax
		xor r11, r11
		mov rax, 12
		shl rax, 3
		mov rax, qword ptr gs:[rax + 0]
		mov rax, [rax + 18h]
		mov rsi, [rax + 20h]
		mov rsi, qword ptr [rsi + 8h]
		lodsq
		xchg rax, rsi
		lodsq
		mov [rax + 20h], rcx
		ret

Patch endp

MoveSyscallAddress proc
		xor r11, r11
		mov r11, rcx
		ret
MoveSyscallAddress endp

end