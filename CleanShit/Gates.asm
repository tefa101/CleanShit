
; WOW
; Obfuscated Assembly 
; ecx contains the ssn or the syscall number


.data 
	dwSyscall DWORD 0000h
	qwSyscallAddress QWORD 0000h
.code 

	GetPeb PROC
		; rcx holds the offset (e.g., 0x60)
		push rbx
		xor rbx, rbx

		; Calculate the address gs:[offset]
		mov rbx, rcx
		mov rax, 0                ; rax = 0
		add rax, rbx              ; rax = rax + offset (rbx)
		nop 
		nop
		mov rax, gs:[rax]         ; rax = gs:[rax]
		nop
		nop
		nop
		nop
		nop
		pop rbx
		nop
		nop
		ret
	GetPeb ENDP


	
	RedroGates PROC
		xor eax , eax					; eax = 0
		nop 
		mov dwSyscall , eax				; dwSyscall = eax = 0 
		mov qwSyscallAddress , rdx      ; qwSyscallAddress = address of the syscall instruction 
		mov eax , ecx					; eax = ssn 
		nop
		mov r8d , eax					; r8d = eax = ssn 
		nop 
		mov dwSyscall , r8d				; dwSyscall = r8d = eax = ssn (syscall)
		nop 
		ret 
	RedroGates ENDP

	RedroExec PROC
		xor r10 ,r10 
		mov rax , rcx					; rax = rcx
		mov r10 , rax					; r10 = rax = rcx 
		nop 
		nop
		mov eax , dwSyscall				; eax = dwSyscall 
		nop
		jmp Redro
		xor eax , eax
		xor rcx , rcx
		nop
	  Redro : 
		jmp qword ptr qwSyscallAddress
		nop
		xor r10 , r10
		nop
		ret
	RedroExec ENDP

END

