		uppercase
		bits		16
		cpu		8086

segment dseg public class=data align=16
hello_str	db		"Hello, world of DOS Programming!", 0Dh, 0Ah
		db		"This is a test.", 0Dh, 0Ah, 0
clarg_str	db		"Command-line arguments: ", 0


segment cseg public class=code align=16
PSP:		resw		1
..start:	mov		word [cs:PSP], ds	; Save pgm seg perfix.
		mov		ax, dseg
		mov		ds, ax
		mov		es, ax
		mov		ax, sseg
		mov		ss, ax
		mov		sp, stack_top
		xor		bp, bp

		; The main routine shall set AL as the %ERRORLEVEL%
		call near	main

		mov		ah, 4Ch
		int		21h


		; Print a zero-terminated string:
main:		mov		ah, 02h

		mov		bx, hello_str
.print_loop:	mov		dl, [bx]
		test		dl, dl
		jz		.loop_exit

		int		21h
		inc		bx
		jmp		.print_loop
.loop_exit:

		; Print the command-line arguments:
		mov		bx, clarg_str
.p2_loop:	mov		dl, [bx]
		test		dl, dl
		jz		.p2_exit

		int		21h
		inc		bx
		jmp		.p2_loop
.p2_exit:
		mov		ds, word [cs:PSP]
		mov		bx, 81h
		xor		ch, ch
		mov		cl, [ds:80h]
		xor		si, si
		test		cx, cx
		jz		.apl_end

.arg_prnt_loop: mov		dl, [ds:bx+si]
		int		21h
		inc		si
		cmp		si, cx
		jne		.arg_prnt_loop

.apl_end:	mov		ax, dseg
		mov		ds, ax
		mov		ah, 02h

		mov		dl, 0Dh
		int		21h
		mov		dl, 0Ah
		int		21h

		xor		al, al
		retn


segment sseg stack class=stack align=16
		resb		2048
stack_top:
