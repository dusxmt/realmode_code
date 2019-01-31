		uppercase
		bits		16
		cpu		8086

		; Include support for fortified DOS system calls:
		%include	"dossyscl.inc"

		; Library routines used:
		extern		sha256_init
		extern		sha256_hash_data
		extern		sha256_finish
		extern		write_str_zterm


segment dseg public class=data align=16
welcome_str	db		"Dooshki's SHA256 command-line text test utility.", 0Dh, 0Ah
		db		0Dh, 0Ah

		db		'SHA256("', 0
mid_str		db		'") = ', 0
newline_str	db		0Dh, 0Ah, 0

checksum_str	resb		64
		db		0


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


		; Prepare the SHA256 module:
main:		call near	sha256_init

		; Show a welcome message:
		mov		bx, stdout
		mov		dx, welcome_str
		call near	write_str_zterm

		; Check command-line arguments:
		mov		ax, [cs:PSP]
		mov		es, ax

		xor		ch, ch
		mov		cl, [es:80h]
		test		cl, cl
		jz		.noargs
		dec		cl		; The first char is always ' '
		jz		.noargs

		; Display the command-line arguments:
		mov		ax, ds
		push		ds
		mov		ax, [cs:PSP]
		mov		ds, ax

		mov		bx, stdout
		mov		dx, 82h
		call near	dos_syscl_hwrite

		pop		ax
		mov		ds, ax

		; Hash the command-line arguments:
		mov		bx, 82h
		mov		dx, bx
		add		dx, cx
		dec		dx
		call near	sha256_hash_data
.noargs:
		; Finalize the hash and convert it into a string:
		call near	sha256_finish

		mov		bx, checksum_str
		call near	gen_256bit_checksum_text

		; Display the results:
		mov		bx, stdout
		mov		dx, mid_str
		call near	write_str_zterm

		mov		dx, checksum_str
		call		write_str_zterm

		mov		dx, newline_str
		call		write_str_zterm

		xor		al, al
		retn


; Generate a text representation of a SHA256 checksum:
;
; Inputs:
;
;   DS:BX - Pointer to where the text representation should be stored.
;   DS:DX - Pointer to the binary version of the checksum.
;
; Outputs:
;
;   64 characters get placed into DS:DX.
;
; The values of all GPRs are preserved.
;
gen_256bit_checksum_text:
		push		ax
		push		bx
		push		cx
		push		si

		mov		si, dx
		add		dx, 8 * 4
		mov		cl, 4

.conv_loop:	mov		al, [si]
		mov		ah, al

		shr		al, cl
		cmp		al, 10
		jb		.ch1_is_b10

		add		al, 'a' - 10
		jmp		.add_ch1

.ch1_is_b10:	add		al, '0'
.add_ch1:	mov		[bx], al
		inc		bx

		and		ah, 0x0F
		cmp		ah, 10
		jb		.ch2_is_b10

		add		ah, 'a' - 10
		jmp		.add_ch2

.ch2_is_b10:	add		ah, '0'
.add_ch2:	mov		[bx], ah
		inc		bx

		inc		si
		cmp		si, dx
		jb		.conv_loop

		pop		si
		pop		cx
		pop		bx
		pop		ax
		retn


segment sseg stack class=stack align=16
		resb		2048
stack_top:
