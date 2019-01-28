		uppercase
		bits		16
		cpu		8086

		; Include support for fortified DOS system calls:
		%include	"dossyscl.inc"

		; Library routines used:
		extern		conv_bin_b64
		extern		conv_b64_bin
		extern		write_str_zterm

segment dseg public class=data align=16
welcome_str	db		"Dooshki's Base64 DOS conversion routines test.", 0Dh, 0Ah
double_nl_str	db		0Dh, 0Ah
newline_str	db		0Dh, 0Ah, 0

no_cmd_args	db		"No command line arguments specified.", 0Dh, 0Ah, 0

src_mes_str	db		"Provided command-line args: ", 0
dest_mes_str	db		"This is the base64 version: ", 0
bcnv_mes_str	db		"And here they are, decoded: ", 0
bin_end_index	resw		1
b64_end_index	resw		1


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


		; Show a welcome message:
main:		mov		bx, stdout
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

		; Copy the command-line arguments into the binary buffer:
		mov		ax, bin_buf_seg
		mov		ds, ax
		xor		bx, bx
.copy1_loop:	mov		al, [es:bx+82h]
		mov		[bx], al
		inc		bx
		cmp		bx, cx
		jb		.copy1_loop

		mov		ax, dseg
		mov		ds, ax
		dec		bx
		mov		[bin_end_index], bx
		jmp		.do_conv

.noargs:	mov		ax, dseg
		mov		ds, ax

		mov		bx, stderr
		mov		dx, no_cmd_args
		call near	write_str_zterm
		mov		al, 1
		retn

		; Perform the conversion into Base64:
.do_conv:	mov		bx, bin_buf_seg
		mov		cx, [bin_end_index]
		mov		dx, b64_buf_seg
		call near	conv_bin_b64
		mov		[b64_end_index], cx

		; Print the message we copied into the "binary" buffer:
		mov		bx, stdout
		mov		dx, src_mes_str
		call near	write_str_zterm

		mov		cx, [bin_end_index]
		inc		cx
		mov		ax, bin_buf_seg
		mov		ds, ax
		xor		dx, dx
		call near	dos_syscl_hwrite

		mov		ax, dseg
		mov		ds, ax

		mov		cx, 4
		mov		dx, double_nl_str
		call near	dos_syscl_hwrite

		; Print the message we copied into the base64 buffer:
		mov		dx, dest_mes_str
		call near	write_str_zterm

		mov		cx, [b64_end_index]
		inc		cx
		mov		ax, b64_buf_seg
		mov		ds, ax
		xor		dx, dx
		call near	dos_syscl_hwrite

		mov		ax, dseg
		mov		ds, ax

		mov		cx, 4
		mov		dx, double_nl_str
		call near	dos_syscl_hwrite


		; Clean out the binary buffer, and then decode the
		; Base64-encoded message:
		call near	clean_bin_buf

		mov		bx, b64_buf_seg
		mov		cx, [b64_end_index]
		mov		dx, bin_buf_seg
		call near	conv_b64_bin
		mov		[bin_end_index], cx

		; Print the decoded message:
		mov		bx, stdout
		mov		dx, bcnv_mes_str
		call near	write_str_zterm

		mov		cx, [bin_end_index]
		inc		cx
		mov		ax, bin_buf_seg
		mov		ds, ax
		xor		dx, dx
		call near	dos_syscl_hwrite

		mov		ax, dseg
		mov		ds, ax

		mov		cx, 2
		mov		dx, newline_str
		call near	dos_syscl_hwrite

		xor		al, al
		retn

; Clean the binary buffer.
;
; The purpose of this routine is to make sure that the "binary" buffer is
; completely empty, mainly for the sake of debugging and demonstrating the
; base64 decoding routine.
;
clean_bin_buf:	mov		ax, es
		push		ax

		mov		ax, bin_buf_seg
		mov		es, ax

		xor		di, di
		xor		dx, dx

		mov		cx, 48 * 1024
.loop:		mov		[es:di], dl
		inc		di
		cmp		di, cx
		jb		.loop
		mov		[bin_end_index], dx
		mov		al, ' '
		mov		[es:0], al

		pop		ax
		mov		es, ax
		retn

; 48K binary data buffer:
segment bin_buf_seg private class=bss align=16
		resb		48 * 1024

; 64K Base64 data buffer:
segment b64_buf_seg private class=bss align=16
		resb		64 * 1024

; 2K stack segment:
segment sseg stack class=stack align=16
		resb		2048
stack_top:
