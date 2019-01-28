		uppercase
		bits		16
		cpu		8086

		; Include support for fortified DOS system calls:
		%include	"dossyscl.inc"

		; Library routines used:
		extern		write_str_zterm
		extern		write_dossyscl_error
		extern		write_u16
		extern		write_s16
		extern		str_identity_check

segment dseg public class=data align=16
newline		db		0Dh, 0Ah
test1_str	db		"write_u16 with a positive number: ", 0
test2_str	db		"write_s16 with a positive number: ", 0
test3_str	db		"write_u16 with a negative number: ", 0
test4_str	db		"write_s16 with a negative number: ", 0
positive_num	dw		32767
negative_num	dw		32769
t5_start_str	db		"(`", 0
t5_middle_str	db		"' == `", 0
t5_end_str	db		"') evaluates to: ", 0
t5_term_str	db		".", 0Dh, 0Ah, 0
t5_str1_str	db		"HeLlO~:2", 0
t5_str2_str	db		"Hello :3", 0
t5_str3_str	db		"This is a test", 0
true_str	db		"TRUE", 0
false_str	db		"FALE", 0


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


		; Main routine:
main:		mov		bx, stdout
		mov		dx, test1_str
		call near	write_str_zterm

		mov		ax, [positive_num]
		call near	write_u16

		mov		cx, 2
		mov		dx, newline
		call near	dos_syscl_hwrite

		mov		bx, stdout
		mov		dx, test2_str
		call near	write_str_zterm

		mov		ax, [positive_num]
		call near	write_s16

		mov		cx, 2
		mov		dx, newline
		call near	dos_syscl_hwrite

		mov		bx, stdout
		mov		dx, test3_str
		call near	write_str_zterm

		mov		ax, [negative_num]
		call near	write_u16

		mov		cx, 2
		mov		dx, newline
		call near	dos_syscl_hwrite

		mov		bx, stdout
		mov		dx, test4_str
		call near	write_str_zterm

		mov		ax, [negative_num]
		call near	write_s16

		mov		cx, 2
		mov		dx, newline
		call near	dos_syscl_hwrite

		; For these comparisons, both strings are in the data segment.
		mov		ax, ds
		mov		es, ax

		mov		bx, t5_str1_str
		mov		dx, t5_str1_str
		call near	test5

		mov		bx, t5_str1_str
		mov		dx, t5_str2_str
		call near	test5

		mov		bx, t5_str1_str
		mov		dx, t5_str3_str
		call near	test5

		mov		bx, t5_str2_str
		mov		dx, t5_str1_str
		call near	test5

		mov		bx, t5_str2_str
		mov		dx, t5_str2_str
		call near	test5

		mov		bx, t5_str2_str
		mov		dx, t5_str3_str
		call near	test5

		mov		bx, t5_str3_str
		mov		dx, t5_str1_str
		call near	test5

		mov		bx, t5_str3_str
		mov		dx, t5_str2_str
		call near	test5

		mov		bx, t5_str3_str
		mov		dx, t5_str3_str
		call near	test5

		mov		bx, stdout
		mov		ax, 5
		call		write_dossyscl_error
		mov		ax, 4
		call		write_dossyscl_error
		mov		ax, 19
		call		write_dossyscl_error
		mov		ax, 15
		call		write_dossyscl_error
		mov		ax, 34
		call		write_dossyscl_error
		mov		ax, 6
		call		write_dossyscl_error

		xor		al, al
		retn

; Test 5: Compare two strings, printing the results:
;
; Inputs:
;
;   DS:BX - First string.
;   DS:DX - Second string.
;
; The values of all GPRs are preserved.
;
test5:		push		bp
		mov		bp, sp
		push		ax	; [bp-2]
		push		bx	; [bp-4]
		push		dx	; [bp-6]

		mov		bx, stdout
		mov		dx, t5_start_str
		call near	write_str_zterm

		mov		dx, [bp-4]
		call near	write_str_zterm

		mov		dx, t5_middle_str
		call near	write_str_zterm

		mov		dx, [bp-6]
		call near	write_str_zterm

		mov		dx, t5_end_str
		call near	write_str_zterm

		pop		dx
		pop		bx
		call near	str_identity_check

		mov		bx, stdout
		jnc		.equal
		mov		dx, false_str
		jmp		.do_print
.equal:		mov		dx, true_str
.do_print:	call near	write_str_zterm

		mov		dx, t5_term_str
		call near	write_str_zterm

		pop		ax
		mov		sp, bp
		pop		bp
		retn

segment sseg stack class=stack align=16
		resb		2048
stack_top:
