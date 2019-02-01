		uppercase
		bits		16
		cpu		8086

		; Include support for fortified DOS system calls:
		%include	"dossyscl.inc"

segment dseg public class=data
ecode_start_str	db		" (error code ", 0
ecode_end_str	db		").", 0Dh, 0Ah, 0

segment cseg public class=code align=16

; Write a zero-terminated string into a file:
;
; Inputs:
;
;   BX    - File handle.
;   DS:DX - Location of the first character of the string.
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set: Error code.
;              - If CF is not set: Number of bytes written to the file.
;
; All other GPRs are preserved.
;
		global		write_str_zterm
write_str_zterm:
		push		cx
		push		bx
		xor		cx, cx
		mov		bx, dx
.count_loop:	mov		al, [bx]
		test		al, al
		jz		.count_done
		inc		bx
		inc		cx
		jmp		.count_loop
.count_done:	pop		bx
		call near	dos_syscl_hwrite
		pop		cx
		retn

; Write an error message for a dos system call error code:
;
;
; This routine is meant to provide a convenient way of printing error messages
; upon the failure of DOS system calls, writing both a descriptive message
; (if the error code is known) and the value of the code itself, terminating
; the output with a dot and a CR LF pair.
;
;
; Inputs:
;
;   AX - Error code
;   BX - File handle
;
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set: Error code.
;              - If CF is not set: Number of bytes written to the file.
;
; All other GPRs are preserved.
;
;
; NOTE:  This routine uses data within this module's and dossyscl.asm's
;        data segment (the text of the messages to be printed), and thus it
;        must be ensured that the data segment of these two modules gets
;        merged (this is the job of the linker) and that the DS register is
;        configured to access it prior to calling this routine.
;
		global		write_dossyscl_error
write_dossyscl_error:
		push		cx
		push		dx

		xor		cx, cx

		push		ax
		call near	dos_syscl_strerror
		call near	write_str_zterm
		jc		.write_failed_pop
		add		cx, ax

		mov		dx, ecode_start_str
		call near	write_str_zterm
		jc		.write_failed_pop
		add		cx, ax

		pop		ax
		call near	write_u16
		jc		.write_failed
		add		cx, ax

		mov		dx, ecode_end_str
		call near	write_str_zterm
		jc		.write_failed
		add		cx, ax

		mov		ax, cx
		pop		dx
		pop		cx
		clc
		retn

.write_failed_pop:
		add		sp, 2	; No need for the old AX value, AX now
					; holds a new error code.
.write_failed:	pop		dx
		pop		cx
		stc
		retn


; Write an unsigned 16-bit number into a file:
;
; Inputs:
;
;   AX  - The number to print.
;   BX  - File handle.
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set: Error code.
;              - If CF is not set: Number of bytes written to the file.
;
; All other GPRs are preserved.
;
		global		write_u16
write_u16:	push		bp
		mov		bp, sp
		; Allocate space on the stack for the number string (6 bytes
		; instead of 5, since sp needs to be even).
		sub		sp, 6	; [bp-1]..[bp-6]

		push		cx
		push		dx
		push		di

		mov		cx, 10
		mov		di, -1

		; Generate a decimal form of the number:
.divide_loop:	xor		dx, dx
		div		cx
		mov		[bp+di], dl
		add		byte [bp+di], '0'
		dec		di
		test		ax, ax
		jnz		.divide_loop

		; Prepare the string far pointer:
		mov		ax, ds
		push		ax
		mov		ax, ss
		mov		ds, ax
		inc		di
		lea		dx, [bp+di]

		; Prepare the length:
		mov		cx, di
		neg		cx

		; Perform the syscall:
		call near	dos_syscl_hwrite

		pop		dx
		mov		ds, dx

		pop		di
		pop		dx
		pop		cx

		mov		sp, bp
		pop		bp
		retn

; Write a signed 16-bit number into a file:
;
; Inputs:
;
;   AX  - The number to print.
;   BX  - File handle.
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set: Error code.
;              - If CF is not set: Number of bytes written to the file.
;
; All other GPRs are preserved.
;
		global		write_s16
write_s16:	push		bp
		mov		bp, sp
		; Allocate space on the stack for the number string:
		sub		sp, 6	; [bp-1]..[bp-6]

		push		cx
		push		dx
		push		di
		push		bx

		mov		cx, 10
		mov		di, -1

		; Check for the sign:
		mov		bx, ax
		and		bx, 8000h
		jz		.divide_loop
		neg		ax

		; Generate a decimal form of the number:
.divide_loop:	xor		dx, dx
		div		cx
		mov		[bp+di], dl
		add		byte [bp+di], '0'
		dec		di
		test		ax, ax
		jnz		.divide_loop

		; Generate a sign if needed:
		test		bx, bx
		jz		.no_sign
		mov		byte [bp+di], '-'
		dec		di
.no_sign:	pop		bx

		; Prepare the string far pointer:
		mov		ax, ds
		push		ax
		mov		ax, ss
		mov		ds, ax
		inc		di
		lea		dx, [bp+di]

		; Prepare the length:
		mov		cx, di
		neg		cx

		; Perform the syscall:
		call near	dos_syscl_hwrite

		pop		dx
		mov		ds, dx

		pop		di
		pop		dx
		pop		cx

		mov		sp, bp
		pop		bp
		retn


; Check whether two zero-terminated strings are equal:
;
; Inputs:
;
;   ES:BX - Start of the first string.
;   DS:DX - Start of the second string.
;
; Outputs:
;
;   The carry flag is unset if the two strings are equal, set otherwise.
;
; The values of all GPRs are preserved.
;
		global		str_identity_check
str_identity_check:
		push		ax
		push		bx
		push		dx

.check_loop:	mov		al, [es:bx]
		xchg		bx, dx
		mov		ah, [bx]
		xchg		bx, dx
		cmp		al, ah
		jnz		.not_equal
		test		al, al
		jz		.are_equal
		inc		bx
		inc		dx
		jmp		.check_loop

.not_equal:	stc
		jmp		.epilogue

.are_equal:	clc

.epilogue:	pop		dx
		pop		bx
		pop		ax
		retn


; Check whether the given character is a space:
;
; A space, in the context of this routine, is one of the following ASCII codes:
; TAB, VT, CR, LF, FF, 20h
;
; Inputs:
;
;   AL - The byte to check
;
; Outputs:
;
;   The carry flag is set if the given byte is not a space, and unset if it is.
;
; The values of all GPRs are preserved.
;
		global		char_is_space
char_is_space:	cmp		al, 09h	; TAB
		jz		.is_space
		cmp		al, 0Bh	; VT
		jz		.is_space
		cmp		al, 0Dh	; CR
		jz		.is_space
		cmp		al, 0Ah	; LF
		jz		.is_space
		cmp		al, 0Ch	; FF
		jz		.is_space
		cmp		al, 20h	; Literal space character
		jz		.is_space

.not_space:	stc
		retn

.is_space:	clc
		retn
