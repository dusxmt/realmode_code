		uppercase
		bits		16
		cpu		8086

segment dseg public class=data
conv_table	db		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


segment cseg public class=code align=16

; Convert binary data into Base64:
;
; This routine converts the raw binary data in the provided input buffer,
; which is described using a segment pointer and the index of the last valid
; byte within the buffer, and places the Base64 representation into a separate
; buffer, also described by a segment pointer, and the index of the last byte
; within this buffer is returned.
;
; The input and output buffers are whole segments; the choice of using segments
; and indexes of the last valid byte was made to allow for the use of an entire
; 64K of memory for the Base64 buffer (with a corresponding 48K binary buffer).
;
; The buffers may be smaller, but it must be ensured that the Base64 buffer has
; a size of at least 4/3 of the size of the raw binary data buffer.
;
;
; Inputs:
;
;   BX - Segment pointer of the input buffer (raw binary representation)
;   CX - Index of the last byte within the input buffer.
;   DX - Segment pointer of the output buffer (Base64 representation)
;
; Outputs:
;
;   Carry flag - Clear to represent success; this routine can't fail.
;   CX         - Index of the last byte within the output buffer.
;
; The value of all other GPRs are preserved.
;
;
; NOTE:  This routine uses data within this module's data segment (the Base64
;        conversion table), and thus it must be ensured that the DS register
;        is configured properly.
;
		global		conv_bin_b64
conv_bin_b64:	push		bp
		mov		bp, sp

		; Save non-return-value GPRs:
		push		ax	; [bp-2]
		push		bx	; [bp-4] Input  buffer segment
		push		dx	; [bp-6] Output buffer segment
		push		si	; [bp-8]
		push		di	; [bp-10]

		; Save the old content of ES, so that we can restore it:
		mov		ax, es
		push		ax	; [bp-12]

		; Prepare index registers:
		xor		si, si
		xor		di, di

		; Info for when to stop:
		mov		dx, cx

		; Access the binary data buffer and read up to 3 bytes from it,
		; filling up the 24-bit BH-BL-CH unit.
.conv_loop:	mov		ax, [bp-4]
		mov		es, ax

		mov		bh, [es:si]
		cmp		si, dx
		jz		.conv_1bt

		inc		si
		mov		bl, [es:si]
		cmp		si, dx
		jz		.conv_2bt

		; CL shall contain the amount of padding bytes to be generated.
		inc		si
		mov		ch, [es:si]
		xor		cl, cl
		jmp		.conv_cont

.conv_1bt:	mov		cl, 2
		xor		bl, bl
		xor		ch, ch
		jmp		.conv_cont

.conv_2bt:	mov		cl, 1
		xor		ch, ch
		jmp		.conv_cont

		; Access the Base64 buffer, output the digits corresponding to
		; the values loaded into BH-BL-CH:
.conv_cont:	mov		ax, [bp-6]
		mov		es, ax
		push		dx
		xor		dx, dx

		; Create the first Base64 digit, we can always do this.
		mov		dl, bh
		shr		dx, 1	; Split into 2 instructions for 8086
		shr		dx, 1	; compatibility.
		xchg		dx, si
		mov		al, [conv_table+si]
		xchg		dx, si
		mov		[es:di], al
		inc		di

		; Create the second Base64 digit, we can always do this.
		mov		dh, cl	; This is just an elaborate way of
		mov		cl, 6	; shifting BX to the left by 6, DH
		shl		bx, cl	; needs to be zero so it makes sense
		mov		cl, dh	; to use it as a backup for cx.
		xor		dh, dh	;

		mov		dl, bh
		shr		dx, 1
		shr		dx, 1
		xchg		dx, si
		mov		al, [conv_table+si]
		xchg		dx, si
		mov		[es:di], al
		inc		di

		; Check whether we're done and need to start padding:
		cmp		cl, 2
		jz		.out_padding

		; Create the third Base64 digit:
		shl		bx, 1
		shl		bx, 1
		mov		bl, ch
		shl		bx, 1	; I could've just done `shl bx, 4', but
		shl		bx, 1	; silly me wants 8086 compatibility...
		shl		bx, 1
		shl		bx, 1
		mov		dl, bh
		shr		dx, 1
		shr		dx, 1
		xchg		dx, si
		mov		al, [conv_table+si]
		xchg		dx, si
		mov		[es:di], al
		inc		di

		; Check whether we're done and need to start padding:
		cmp		cl, 1
		jz		.out_padding

		; Create the fourth Base64 digit:
		mov		dh, cl
		mov		cl, 6
		shl		bx, cl
		mov		cl, dh
		xor		dh, dh

		mov		dl, bh
		shr		dx, 1
		shr		dx, 1
		xchg		dx, si
		mov		al, [conv_table+si]
		xchg		dx, si
		mov		[es:di], al
		inc		di

		jmp		.out_done

.out_padding:	mov		al, '='
		mov		[es:di], al
		inc		di
		dec		cl
		jnz		.out_padding

.out_done:	pop		dx

		; SI contains the last processed byte; was it the last one?
		cmp		si, dx
		jz		.epilogue

		; If not, more work is ahead of us!
		inc		si
		jmp		.conv_loop

.epilogue:	dec		di
		mov		cx, di

		; Restore ES:
		pop		ax
		mov		es, ax

		; Restore the non-return-value GPRs:
		pop		di
		pop		si
		pop		dx
		pop		bx
		pop		ax
		
		; Report success and exit:
		clc
		mov		sp, bp
		pop		bp
		retn

; Decode Base64-encoded data into raw binary:
;
; This routine decodes the Base64-encoded data in the provided input buffer,
; which is described using a segment pointer and the index of the last valid
; character within the buffer, and places the raw binary representation into
; a separate buffer, also described by a segment pointer, and the index of the
; last byte within this buffer is returned.
;
; This routine can fail if the input is not valid Base64-encoded data, and will
; set the carry flag if this happens.
;
; The input and output buffers are whole segments; the choice of using segments
; and indexes of the last valid byte was made to allow for the use of an entire
; 64K of memory for the Base64 buffer (with a corresponding 48K binary buffer).
;
; The buffers may be smaller, but it must be ensured that the raw binary buffer
; has a size of at least 3/4 of the size of the Base64 data buffer.
;
;
; Inputs:
;
;   BX - Segment pointer of the input buffer (Base64 representation)
;   CX - Index of the last byte within the input buffer.
;   DX - Segment pointer of the output buffer (Raw binary representation)
;
; Outputs:
;   Carry flag - Clear on success, set on failure (invalid input).
;   CX         - Index of the last byte within the output buffer.
;
; The value of all other GPRs are preserved.
;
;
; NOTE:  This routine uses data within this module's data segment (the Base64
;        conversion table), and thus it must be ensured that the DS register
;        is configured properly.
;
		global		conv_b64_bin
conv_b64_bin:	push		bp
		mov		bp, sp

		; Save non-return-value GPRs:
		push		ax	; [bp-2]
		push		bx	; [bp-4] Input  buffer segment
		push		dx	; [bp-6] Output buffer segment
		push		si	; [bp-8]
		push		di	; [bp-10]

		; Save the old content of ES, so that we can restore it:
		mov		ax, es
		push		ax	; [bp-12]

		; Prepare index registers:
		xor		si, si
		xor		di, di

		; Info for when to stop:
		mov		dx, cx

		; Access the buffer with the Base64-encoded data, and load
		; (up to) 4 Base64 digits into the 24-bit BH-BL-CH unit.
		;
		; CL shall represent how many raw bytes the BH-BL-CH unit
		; represents.
.conv_loop:	mov		ax, [bp-4]
		mov		es, ax
		mov		cl, 3
		xor		bx, bx
		xor		ch, ch

		; The first digit within a 3-byte block is mandatory:
		mov		al, [es:si]
		call near	b64_digit_decode
		jc		.decode_fail
		mov		bl, al
		mov		ah, 6
		xchg		cl, ah
		shl		bx, cl
		mov		cl, ah

		; The second digit within a 3-byte block is mandatory as well:
		cmp		si, dx
		jz		.decode_fail
		inc		si
		mov		al, [es:si]
		call near	b64_digit_decode
		jc		.decode_fail
		or		bl, al
		mov		ah, 4
		xchg		cl, ah
		shl		bx, cl
		mov		cl, ah

		; The third digit within a 3-byte block is optional:
		cmp		si, dx		; If it's missing, assume pad.
		jz		.pad_d3
.load_d3:	inc		si
		mov		al, [es:si]
		cmp		al, '='
		jnz		.decode_d3
.pad_d3:	xor		al, al
		dec		cl
		jmp		.have_d3
.decode_d3:	call near	b64_digit_decode
		jc		.decode_fail
.have_d3:	mov		ch, al		; Store the top 4 bits into
		shr		ch, 1		; the free 4 bits in BX.
		shr		ch, 1
		or		bl, ch
		mov		ch, al		; Store the bottom 2 bits into
		and		ch, 0x3		; the two MSBs of CH.
		mov		ah, 6
		xchg		cl, ah
		shl		ch, cl
		mov		cl, ah

		; The fourth digit within a 3-byte block is optional as well:
		cmp		si, dx		; If it's missing, assume pad.
		jz		.pad_d4
.load_d4:	inc		si
		mov		al, [es:si]
		cmp		al, '='
		jnz		.decode_d4
.pad_d4:	xor		al, al
		dec		cl
		jmp		.have_d4
.decode_d4:	call near	b64_digit_decode
		jc		.decode_fail
.have_d4:	or		ch, al

		; The 24-bit BH-BL-CH unit has been successfully loaded with
		; decoded information, we can store it into the output buffer:
		mov		ax, [bp-6]
		mov		es, ax
		mov		[es:di], bh
		inc		di
		dec		cl
		jz		.done
		mov		[es:di], bl
		inc		di
		dec		cl
		jz		.done
		mov		[es:di], ch
		inc		di

.done:		cmp		si, dx
		jz		.all_done
		inc		si
		jmp		.conv_loop

		; On failure, put a question mark at the end of successfully
		; decoded data in the output buf, might be useful for debug:
.decode_fail:	mov		ax, [bp-6]
		mov		es, ax
		mov		byte [es:di], '?'
		mov		cx, di

		clc
		cmc
		jmp		.epilogue

.all_done:	dec		di
		mov		cx, di
		clc

		; Restore ES:	
.epilogue:	pop		ax
		mov		es, ax

		; Restore the non-return-value GPRs:
		pop		di
		pop		si
		pop		dx
		pop		bx
		pop		ax
		
		mov		sp, bp
		pop		bp
		retn

; Decode the provided character as a Base64 digit:
;
; This routine goes down the conversion table and searches for the appropriate
; numeric value for the given ascii character that represents a Base64 digit.
;
; Inputs:
;
;   AL - The ASCII representation of the digit in question.
;
; Outputs:
;
;   Carry flag - Clear on success, set on failure.
;   AX         - The numeric value of the digit on success, 0 otherwise.
;
; The value of all other GPRs are preserved.
;
b64_digit_decode:
		push	bx
		xor	bx, bx

.search_loop:	mov	ah, [conv_table+bx]
		cmp	ah, al
		jz	.found

		inc	bx
		cmp	bx, 64
		jb	.search_loop

		; The input is invalid, we found no match in the conv. table.
		xor	ax, ax
		pop	bx

		clc
		cmc
		retn

.found:		mov	al, bl
		xor	ah, ah
		pop	bx
		clc
		retn
