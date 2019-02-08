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
		extern		write_dossyscl_error
		extern		char_is_space


segment dseg public class=data align=16
welcome_str	db		"Dooshki's SHA256 file checksum generation utility.", 0Dh, 0Ah
newline_str	db		0Dh, 0Ah, 0

no_fname	db		"No file name specified.", 0Ah, 0Dh, 0

opening_p1_str	db		"Opening `", 0
opening_p2_str	db		"' for reading... ", 0

success_str	db		"ok.", 0Ah, 0Dh, 0
fail_str	db		"failed: ", 0

process_str	db		"Reading and examining the file... ", 0
done_str	db		"done.", 0Ah, 0Dh, 0
rfail_str	db		"read failed: ", 0
result_sep_str	db		" - ", 0

		; Given how in DOS, command-line argumetns are provided to the
		; program in a string at most 127 bytes long, for the worst
		; case scenario of a filename occupying the entire string, set
		; aside 127 + 1 (zero termination) bytes for the file name.
fname_str	resb		128
file_handle	resw		1

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


		; Show a welcome message:
main:		mov		bx, stdout
		mov		dx, welcome_str
		call near	write_str_zterm

		; Collect the first word from the cmdargs as a filename:
		mov		ax, [cs:PSP]
		mov		es, ax

		xor		ch, ch
		mov		cl, [es:80h]

		mov		si, 81h
		mov		dx, si
		add		dx, cx
		mov		di, fname_str

.skipsp_loop:	cmp		si, dx
		jnb		.fnread_done

		mov		al, [es:si]
		call near	char_is_space
		jc		.read_fname
		inc		si
		jmp		.skipsp_loop

.fnread_loop:	cmp		si, dx
		jnb		.fnread_done

		mov		al, [es:si]
		call near	char_is_space
		jnc		.fnread_done

.read_fname:	mov		[di], al
		inc		si
		inc		di
		jmp		.fnread_loop

.fnread_done:	mov		byte [di], 0

		; Is there a filename?
		mov		al, byte [fname_str]
		test		al, al
		jnz		.have_fname

		mov		bx, stdout
		mov		dx, no_fname
		call near	write_str_zterm
		mov		al, 1
		retn

.have_fname:	mov		bx, stdout
		mov		dx, opening_p1_str
		call near	write_str_zterm

		mov		dx, fname_str
		call near	write_str_zterm

		mov		dx, opening_p2_str
		call near	write_str_zterm

		mov		al, file_read_only
		mov		dx, fname_str
		call near	dos_syscl_hfopen
		jnc		.file_open
		
		push		ax
		mov		bx, stdout
		mov		dx, fail_str
		call near	write_str_zterm

		pop		ax
		call near	write_dossyscl_error

		mov		al, 2
		retn

.file_open:	mov		[file_handle], ax
		mov		bx, stdout
		mov		dx, success_str
		call near	write_str_zterm

		; Prepare the SHA256 module:
		call near	sha256_init

		; Have access to the buffer segment ready:
		mov		si, read_buf_seg
		mov		di, ds
		mov		es, si

		; Print a string to inform the user of the process:
		mov		bx, stdout
		mov		dx, process_str
		call near	write_str_zterm

		; Since our buffer is 64K long, which is 1 byte more than
		; the DOS "handle" read routine can handle, fill it using
		; two 32K reads:
.read_loop:	mov		bx, [file_handle]
		mov		cx, 32 * 1024
		mov		ds, si
		xor		dx, dx
		call near	dos_syscl_hread
		jc		.read_failed
		test		ax, ax
		jz		.read_done

		; Did we read less than 32K?  No need to read more then.
		cmp		ax, cx
		jb		.read2_not_needed

		push		ax
		mov		dx, cx
		call near	dos_syscl_hread
		jc		.read_failed

		pop		cx
		add		ax, cx

.read2_not_needed:
		mov		ds, di
		xor		bx, bx
		mov		dx, ax
		dec		dx
		call near	sha256_hash_data

		jmp		.read_loop

.read_failed:	mov		ds, di
		push		ax
		mov		bx, stdout
		mov		dx, rfail_str
		call near	write_str_zterm

		pop		ax
		call near	write_dossyscl_error

		mov		bx, [file_handle]
		call near	dos_syscl_hclose

		mov		al, 3
		retn

.read_done:	mov		ds, di

		mov		bx, [file_handle]
		call near	dos_syscl_hclose

		mov		bx, stdout
		mov		dx, done_str
		call near	write_str_zterm

		; Finalize the hash and convert it into a string:
		call near	sha256_finish

		mov		bx, checksum_str
		call near	gen_256bit_checksum_text

		; Display the results:
		mov		bx, stdout
		mov		dx, newline_str
		call near	write_str_zterm

		mov		dx, checksum_str
		call near	write_str_zterm

		mov		dx, result_sep_str
		call near	write_str_zterm

		mov		dx, fname_str
		call near	write_str_zterm

		mov		dx, newline_str
		call near	write_str_zterm

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


segment read_buf_seg bss class=bss align=16
		resb		64 * 1024

segment sseg stack class=stack align=16
		resb		2048
stack_top:
