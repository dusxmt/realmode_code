		uppercase
		bits		16
		cpu		8086

; This module provides a SHA256 hash implementation for the 8086.
;
; This implementation works on messages of a multiple of 8 bits (that is, it's
; byte-oriented), and with the current implementation can only calculate the
; hash of 1 message at a time (due to the use of a global state; this might
; be changed later down the line, it shouldn't be difficult to do).
;
; The internal state of the library is kept in the form of little-endian 32-bit
; words that are accessed and manipulated by dedicated routines.  This perhaps
; makes the code slow, but it also makes it clear and understandable, which is
; more important to me given that this project is mainly a learning experience,
; I would not have restricted myself to the 8086 instruction set had I cared
; about performance.
;
; The routine sha256_init initializes the internal state of the module and
; prepares it for data processing.
;
; The routine sha256_hash_data takes the provided buffer of data, fills the
; message buffer with it, and upon each fill of 64 bytes it iterates thorugh
; the hashing process.
;
; The routine sha256_finish terminates the message, adding in a 1 bit at the
; end, followed by a sufficient amount of zeroes and the message length,
; rounding the message off to 512 bits, and after a final hashing iteration,
; it reverses the bytes within the hash buffer so that it's big-endian,
; returning a pointer to this buffer within this module's data segment.  This
; buffer is valid as long as no routine provided by this module is invoked.
;
segment dseg public class=data
		align		4

; Initial hash value, obtained by taking the fractal parts of the square roots
; of the first eight primes:
;
hash_init:	dd		06A09E667h
		dd		0BB67AE85h
		dd		03C6EF372h
		dd		0A54FF53Ah
		dd		0510E527Fh
		dd		09B05688Ch
		dd		01F83D9ABh
		dd		05BE0CD19h

; The first thirty-two bits of the fractional parts of the cube roots of the
; first sixty-four primes:
;
k_table:	; k[0] to k[7]:
		dd		0428A2F98h
		dd		071374491h
		dd		0B5C0FBCFh
		dd		0E9B5DBA5h
		dd		03956C25Bh
		dd		059F111F1h
		dd		0923F82A4h
		dd		0AB1C5ED5h

		; k[8] to k[15]:
		dd		0D807AA98h
		dd		012835B01h
		dd		0243185BEh
		dd		0550C7DC3h
		dd		072BE5D74h
		dd		080DEB1FEh
		dd		09BDC06A7h
		dd		0C19BF174h

		; k[15] to k[23]:
		dd		0E49B69C1h
		dd		0EFBE4786h
		dd		00FC19DC6h
		dd		0240CA1CCh
		dd		02DE92C6Fh
		dd		04A7484AAh
		dd		05CB0A9DCh
		dd		076F988DAh

		; k[23] to k[31]:
		dd		0983E5152h
		dd		0A831C66Dh
		dd		0B00327C8h
		dd		0BF597FC7h
		dd		0C6E00BF3h
		dd		0D5A79147h
		dd		006CA6351h
		dd		014292967h

		; k[32] to k[39]:
		dd		027B70A85h
		dd		02E1B2138h
		dd		04D2C6DFCh
		dd		053380D13h
		dd		0650A7354h
		dd		0766A0ABBh
		dd		081C2C92Eh
		dd		092722C85h

		; k[40] to k[47]:
		dd		0A2BFE8A1h
		dd		0A81A664Bh
		dd		0C24B8B70h
		dd		0C76C51A3h
		dd		0D192E819h
		dd		0D6990624h
		dd		0F40E3585h
		dd		0106AA070h

		; k[48] to k[55]:
		dd		019A4C116h
		dd		01E376C08h
		dd		02748774Ch
		dd		034B0BCB5h
		dd		0391C0CB3h
		dd		04ED8AA4Ah
		dd		05B9CCA4Fh
		dd		0682E6FF3h

		; k[56] to k[63]:
		dd		0748F82EEh
		dd		078A5636Fh
		dd		084C87814h
		dd		08CC70208h
		dd		090BEFFFAh
		dd		0A4506CEBh
		dd		0BEF9A3F7h
		dd		0C67178F2h

; 64-Entry Message Schedule Array:
w_array:	resd		64

; Current hash value array:
hash_current:	resd		8
message_bits:	resq		1

; Message chunk buffer:
m_array:	resd		16
bytes_in_m:	resw		1


segment cseg public class=code align=16

; Add a 16-bit number to a 64-bit number:
;
; Inputs:
;
;   CX    - The 16-bit value (unsigned) to add to the 64-bit number.
;   DS:DX - Pointer to the 64-bit number to add CX to.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
;
add_64_16:	push		ax
		push		cx
		xchg		bx, dx

		mov		ax, [bx]
		add		ax, cx
		mov		[bx], ax

		mov		cx, 0	; Can't use XOR here since it clears
					; the carry flag.

		mov		ax, [bx+2]
		adc		ax, cx
		mov		[bx+2], ax

		mov		ax, [bx+4]
		adc		ax, cx
		mov		[bx+4], ax

		mov		ax, [bx+6]
		adc		ax, cx
		mov		[bx+6], ax

		xchg		bx, dx
		pop		cx
		pop		ax
		retn

; Add two 32-bit numbers modulo 2^32 (whihch basically means discarding carry):
;
; Inputs:
;
;   DS:BX - Pointer to Number 1 (little-endian 32-bit word).
;   DS:CX - Pointer to Number 2 (little-endian 32-bit word).
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
add_modulo_2_32:
		push		ax

		mov		ax, [bx]
		xchg		bx, cx
		add		ax, [bx]
		xchg		bx, cx
		xchg		bx, dx
		mov		[bx], ax
		xchg		bx, dx

		mov		ax, [bx+2]
		xchg		bx, cx
		adc		ax, [bx+2]
		xchg		bx, cx
		xchg		bx, dx
		mov		[bx+2], ax
		xchg		bx, dx

		pop		ax
		retn

; Bitwise AND of two 32-bit numbers:
;
; Inputs:
;
;   DS:BX - Pointer to Number 1.
;   DS:CX - Pointer to Number 2.
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
and_32_32:	push		ax

		mov		ax, [bx]
		xchg		bx, cx
		and		ax, [bx]
		xchg		bx, cx
		xchg		bx, dx
		mov		[bx], ax
		xchg		bx, dx

		mov		ax, [bx+2]
		xchg		bx, cx
		and		ax, [bx+2]
		xchg		bx, cx
		xchg		bx, dx
		mov		[bx+2], ax
		xchg		bx, dx

		pop		ax
		retn

; Bitwise OR of two 32-bit numbers:
;
; Inputs:
;
;   DS:BX - Pointer to Number 1.
;   DS:CX - Pointer to Number 2.
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
or_32_32:	push		ax

		mov		ax, [bx]
		xchg		bx, cx
		or		ax, [bx]
		xchg		bx, cx
		xchg		bx, dx
		mov		[bx], ax
		xchg		bx, dx

		mov		ax, [bx+2]
		xchg		bx, cx
		or		ax, [bx+2]
		xchg		bx, cx
		xchg		bx, dx
		mov		[bx+2], ax
		xchg		bx, dx

		pop		ax
		retn

; Bitwise XOR of two 32-bit numbers:
;
; Inputs:
;
;   DS:BX - Pointer to Number 1.
;   DS:CX - Pointer to Number 2.
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
xor_32_32:
		push		ax

		mov		ax, [bx]
		xchg		bx, cx
		xor		ax, [bx]
		xchg		bx, cx
		xchg		bx, dx
		mov		[bx], ax
		xchg		bx, dx

		mov		ax, [bx+2]
		xchg		bx, cx
		xor		ax, [bx+2]
		xchg		bx, cx
		xchg		bx, dx
		mov		[bx+2], ax
		xchg		bx, dx

		pop		ax
		retn

; Bitwise complement of a 32-bit number:
;
; Inputs:
;
;   DS:BX - Pointer to the number to complement.
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
complement_32:	push		ax

		mov		ax, [bx]
		not		ax
		xchg		bx, dx
		mov		[bx], ax
		xchg		bx, dx

		mov		ax, [bx+2]
		not		ax
		xchg		bx, dx
		mov		[bx+2], ax
		xchg		bx, dx

		pop		ax
		retn

; Logical right shift of a 32-bit number:
;
; Inputs:
;
;   DS:BX - Pointer to the number to shift (little-endian 32-bit word).
;   CL    - The amount of bits to shift.
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
shift_right_32: push		ax

		cmp		cl, 32
		jb		.do_shift

		; If we're to shift by 32 or more, the result is a zero.
		xchg		bx, dx
		mov		word [bx], 0
		mov		word [bx+2], 0
		xchg		bx, dx

		pop		ax
		retn

		; If we're to shift by 16 or more, we lose the low-orer word.
.do_shift:	cmp		cl, 16
		jb		.full_shift

		mov		ax, [bx+2]
		sub		cl, 16
		jz		.skip_shift
		shr		ax, cl
.skip_shift:
		xchg		bx, dx
		mov		[bx], ax
		mov		word [bx+2], 0
		xchg		bx, dx

		add		cl, 16
		pop		ax
		retn

.full_shift:	test		cl, cl
		jz		.just_copy
		mov		ax, [bx]
		push		si
		shr		ax, cl
		mov		si, ax

		mov		ax, [bx+2]
		neg		cl		; CL <- (16 - CL)
		add		cl, 16
		shl		ax, cl
		or		ax, si
		sub		cl, 16		; Restore CL.
		neg		cl
		pop		si		; Restore SI as well.

		xchg		bx, dx
		mov		[bx], ax
		xchg		bx, dx

		mov		ax, [bx+2]
		shr		ax, cl
		xchg		bx, dx
		mov		[bx+2], ax
		xchg		bx, dx

		pop		ax
		retn

.just_copy:	push		cx
		mov		ax, [bx]
		mov		cx, [bx+2]
		xchg		bx, dx
		mov		[bx], ax
		mov		[bx+2], cx
		xchg		bx, dx
		pop		cx

		pop		ax
		retn


; Logical left shift of a 32-bit number:
;
; Inputs:
;
;   DS:BX - Pointer to the number to shift (little-endian 32-bit word).
;   CL    - The amount of bits to shift.
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
shift_left_32:	push		ax

		cmp		cl, 32
		jb		.do_shift

		; If we're to shift by 32 or more, the result is a zero.
		xchg		bx, dx
		mov		word [bx], 0
		mov		word [bx+2], 0
		xchg		bx, dx

		pop		ax
		retn

		; If we're to shift by 16 or more, we lose the high-order word.
.do_shift:	cmp		cl, 16
		jb		.full_shift

		mov		ax, [bx]
		sub		cl, 16
		jz		.skip_shift
		shl		ax, cl
.skip_shift:
		xchg		bx, dx
		mov		[bx+2], ax
		mov		word [bx], 0
		xchg		bx, dx

		add		cl, 16
		pop		ax
		retn

.full_shift:	test		cl, cl
		jz		.just_copy
		mov		ax, [bx+2]
		push		si
		shl		ax, cl
		mov		si, ax

		mov		ax, [bx]
		neg		cl		; CL <- (16 - CL)
		add		cl, 16
		shr		ax, cl
		or		ax, si
		sub		cl, 16		; Restore CL.
		neg		cl
		pop		si		; Restore SI as well.

		xchg		bx, dx
		mov		[bx+2], ax
		xchg		bx, dx

		mov		ax, [bx]
		shl		ax, cl
		xchg		bx, dx
		mov		[bx], ax
		xchg		bx, dx

		pop		ax
		retn

.just_copy:	push		cx
		mov		ax, [bx]
		mov		cx, [bx+2]
		xchg		bx, dx
		mov		[bx], ax
		mov		[bx+2], cx
		xchg		bx, dx
		pop		cx

		pop		ax
		retn


; Bitwise right rotate of a 32-bit number:
;
; Inputs:
;
;   DS:BX - Pointer to the number to rotate (little-endian 32-bit word).
;   CL    - The amount of bits to rotate by.
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
rotate_right_32:
		push		bp
		mov		bp, sp

		; Allocate 2 32-bit variables on the stack:
		sub		sp, 8	; [bp-4] and [bp-8]

		push		ax
		push		cx

		; Make two copies of the number to rotate:
		mov		ax, [bx]
		mov		[bp-4], ax
		mov		[bp-8], ax

		mov		ax, [bx+2]
		mov		[bp-2], ax
		mov		[bp-6], ax

		push		bx
		push		dx
		push		si
		mov		si, ds
		mov		ax, ss
		mov		ds, ax

		; Rotate is a periodic function, with a period of 32, get the
		; modulo_32 of CL:
		and		cl, 31
		jz		.just_copy

		; Shift one copy to the right by CL bits:
		lea		bx, [bp-4]
		lea		dx, [bp-4]
		call near	shift_right_32

		; Shift the other copy to the left by 32-CL bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		neg		cl
		add		cl, 32
		call near	shift_left_32

		; Let [bp-4] <- [bp-4] | [bp-8]:
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	or_32_32

.just_copy:	mov		ds, si
		pop		si
		pop		bx	; Note: BX and DX are intentionally
		pop		dx	; restored reversed.

		; Store the result from [bp-4] into DS:DX
		mov		ax, [bp-4]
		mov		[bx], ax
		mov		ax, [bp-2]
		mov		[bx+2], ax
		xchg		bx, dx

		pop		cx
		pop		ax

		mov		sp, bp
		pop		bp
		retn

; Perform the Ch(x, y, z) function:
;
; The Ch(x, z, y) function is defined as follows:
;
;   (X AND Y) XOR (complement(X) AND Z)
;
;
; Inputs:
;
;   DS:BX - Argument X (pointer to a 32-bit little-endian number).
;   DS:CX - Argument Y (pointer to a 32-bit little-endian number).
;   DS:SI - Argument Z (pointer to a 32-bit little-endian number).
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
sha_function_ch_xyz:
		push		bp
		mov		bp, sp

		; Allocate 3 32-bit variables on the stack:
		sub		sp, 12	; [bp-4], [bp-8], [bp-12]

		; Back AX and ES up:
		push		ax	; [bp-14]
		mov		ax, es
		push		ax	; [bp-16]

		push		bx	; [bp-18]
		push		cx	; [bp-20]
		push		dx	; [bp-22]
		push		di	; [bp-24]

		; DI <- DS, ES <- DS, DS <- SS.
		mov		di, ds
		mov		es, di
		mov		ax, ss
		mov		ds, ax

		; Load X and Y into [bp-4] and [bp-8]:
		mov		ax, [es:bx]
		mov		[bp-4], ax
		mov		ax, [es:bx+2]
		mov		[bp-2], ax

		mov		bx, cx
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Let [bp-4] <- [bp-4] & [bp-8]:
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	and_32_32

		; Load X into [bp-8] and bitwise complement it:
		mov		bx, [bp-18]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		call near	complement_32

		; Load Z into [bp-12], then let [bp-8] <- [bp-8] & [bp-12]:
		mov		ax, [es:si]
		mov		[bp-12], ax
		mov		ax, [es:si+2]
		mov		[bp-10], ax
		lea		dx, [bp-8]
		lea		bx, [bp-8]
		lea		cx, [bp-12]
		call near	and_32_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]:
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; The anser is in [bp-4], stash it:
		mov		bx, [bp-22]
		mov		ax, [bp-4]
		mov		[es:bx], ax
		mov		ax, [bp-2]
		mov		[es:bx+2], ax

		; Restore the data segment register and GPRs:
		mov		ds, di

		pop		di
		pop		dx
		pop		cx
		pop		bx

		; Restore AX and ES:
		pop		ax
		mov		es, ax
		pop		ax

		mov		sp, bp
		pop		bp
		retn

; Perform the Maj(x, y, z) function:
;
; The Maj(x, z, y) function is defined as follows:
;
;   (X AND Y) XOR (X AND Z) XOR (Y AND Z)
;
;
; Inputs:
;
;   DS:BX - Argument X (pointer to a 32-bit little-endian number).
;   DS:CX - Argument Y (pointer to a 32-bit little-endian number).
;   DS:SI - Argument Z (pointer to a 32-bit little-endian number).
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
sha_function_maj_xyz:
		push		bp
		mov		bp, sp

		; Allocate 3 32-bit variables on the stack:
		sub		sp, 12	; [bp-4], [bp-8], [bp-12]

		; Back AX and ES up:
		push		ax	; [bp-14]
		mov		ax, es
		push		ax	; [bp-16]

		push		bx	; [bp-18]
		push		cx	; [bp-20]
		push		dx	; [bp-22]
		push		di	; [bp-24]

		; DI <- DS, ES <- DS, DS <- SS.
		mov		di, ds
		mov		es, di
		mov		ax, ss
		mov		ds, ax

		; Load X and Y into [bp-4] and [bp-8]:
		mov		ax, [es:bx]
		mov		[bp-4], ax
		mov		ax, [es:bx+2]
		mov		[bp-2], ax

		mov		bx, cx
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Let [bp-4] <- [bp-4] & [bp-8]:
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	and_32_32

		; Load X and Z into [bp-8] and [bp-12]:
		mov		bx, [bp-18]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		mov		ax, [es:si]
		mov		[bp-12], ax
		mov		ax, [es:si+2]
		mov		[bp-10], ax

		; Let [bp-8] <- [bp-8] & [bp-12]:
		lea		dx, [bp-8]
		lea		bx, [bp-8]
		lea		cx, [bp-12]
		call near	and_32_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]:
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; Load Y into [bp-8], note: [bp-12] already contains Z.
		mov		bx, [bp-20]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Let [bp-8] <- [bp-8] & [bp-12]:
		lea		dx, [bp-8]
		lea		bx, [bp-8]
		lea		cx, [bp-12]
		call near	and_32_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]:
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; The anser is in [bp-4], stash it:
		mov		bx, [bp-22]
		mov		ax, [bp-4]
		mov		[es:bx], ax
		mov		ax, [bp-2]
		mov		[es:bx+2], ax

		; Restore the data segment register and GPRs:
		mov		ds, di

		pop		di
		pop		dx
		pop		cx
		pop		bx

		; Restore AX and ES:
		pop		ax
		mov		es, ax
		pop		ax

		mov		sp, bp
		pop		bp
		retn

; Perform the upper-case Sigma0(x) function:
;
; The upper-case Sigma0(x) function is defined as follows:
;
;   ROR(X, 2) XOR ROR(X, 13) XOR ROR(X, 22)
;
;
; Inputs:
;
;   DS:BX - Argument X (pointer to a 32-bit little-endian number).
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
uc_sigma0:	push		bp
		mov		bp, sp

		; Allocate 2 32-bit variables on the stack:
		sub		sp, 8	; [bp-4], [bp-8]

		; Back AX and ES up:
		push		ax	; [bp-10]
		mov		ax, es
		push		ax	; [bp-12]

		push		bx	; [bp-14]
		push		cx	; [bp-16]
		push		dx	; [bp-18]
		push		di	; [bp-20]

		; DI <- DS, ES <- DS, DS <- SS.
		mov		di, ds
		mov		es, di
		mov		ax, ss
		mov		ds, ax

		; Load X into [bp-4]:
		mov		ax, [es:bx]
		mov		[bp-4], ax
		mov		ax, [es:bx+2]
		mov		[bp-2], ax

		; Rotate [bp-4] right by 2 bits:
		lea		bx, [bp-4]
		lea		dx, [bp-4]
		mov		cl, 2
		call near	rotate_right_32

		; Load X into [bp-8]:
		mov		bx, [bp-14]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Rotate [bp-8] right by 13 bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		mov		cl, 13
		call near	rotate_right_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; Load X into [bp-8]:
		mov		bx, [bp-14]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Rotate [bp-8] right by 22 bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		mov		cl, 22		; TODO: Skip the above load and
		call near	rotate_right_32	; rotate by 9.

		; Let [bp-4] <- [bp-4] ^ [bp-8]
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; The anser is in [bp-4], stash it:
		mov		bx, [bp-18]
		mov		ax, [bp-4]
		mov		[es:bx], ax
		mov		ax, [bp-2]
		mov		[es:bx+2], ax

		; Restore the data segment register and GPRs:
		mov		ds, di

		pop		di
		pop		dx
		pop		cx
		pop		bx

		; Restore AX and ES:
		pop		ax
		mov		es, ax
		pop		ax

		mov		sp, bp
		pop		bp
		retn

; Perform the upper-case Sigma1(x) function:
;
; The upper-case Sigma1(x) function is defined as follows:
;
;   ROR(X, 6) XOR ROR(X, 11) XOR ROR(X, 25)
;
;
; Inputs:
;
;   DS:BX - Argument X (pointer to a 32-bit little-endian number).
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
uc_sigma1:	push		bp
		mov		bp, sp

		; Allocate 2 32-bit variables on the stack:
		sub		sp, 8	; [bp-4], [bp-8]

		; Back AX and ES up:
		push		ax	; [bp-10]
		mov		ax, es
		push		ax	; [bp-12]

		push		bx	; [bp-14]
		push		cx	; [bp-16]
		push		dx	; [bp-18]
		push		di	; [bp-20]

		; DI <- DS, ES <- DS, DS <- SS.
		mov		di, ds
		mov		es, di
		mov		ax, ss
		mov		ds, ax

		; Load X into [bp-4]:
		mov		ax, [es:bx]
		mov		[bp-4], ax
		mov		ax, [es:bx+2]
		mov		[bp-2], ax

		; Rotate [bp-4] right by 6 bits:
		lea		bx, [bp-4]
		lea		dx, [bp-4]
		mov		cl, 6
		call near	rotate_right_32

		; Load X into [bp-8]:
		mov		bx, [bp-14]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Rotate [bp-8] right by 11 bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		mov		cl, 11
		call near	rotate_right_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; Load X into [bp-8]:
		mov		bx, [bp-14]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Rotate [bp-8] right by 25 bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		mov		cl, 25		; TODO: Skip the above load and
		call near	rotate_right_32	; rotate by 14.

		; Let [bp-4] <- [bp-4] ^ [bp-8]
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; The anser is in [bp-4], stash it:
		mov		bx, [bp-18]
		mov		ax, [bp-4]
		mov		[es:bx], ax
		mov		ax, [bp-2]
		mov		[es:bx+2], ax

		; Restore the data segment register and GPRs:
		mov		ds, di

		pop		di
		pop		dx
		pop		cx
		pop		bx

		; Restore AX and ES:
		pop		ax
		mov		es, ax
		pop		ax

		mov		sp, bp
		pop		bp
		retn


; Perform the lower-case Sigma0(x) function:
;
; The lower-case Sigma0(x) function is defined as follows:
;
;   ROR(X, 7) XOR ROR(X, 18) XOR SHR(X, 3)
;
;
; Inputs:
;
;   DS:BX - Argument X (pointer to a 32-bit little-endian number).
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
lc_sigma0:	push		bp
		mov		bp, sp

		; Allocate 2 32-bit variables on the stack:
		sub		sp, 8	; [bp-4], [bp-8]

		; Back AX and ES up:
		push		ax	; [bp-10]
		mov		ax, es
		push		ax	; [bp-12]

		push		bx	; [bp-14]
		push		cx	; [bp-16]
		push		dx	; [bp-18]
		push		di	; [bp-20]

		; DI <- DS, ES <- DS, DS <- SS.
		mov		di, ds
		mov		es, di
		mov		ax, ss
		mov		ds, ax

		; Load X into [bp-4]:
		mov		ax, [es:bx]
		mov		[bp-4], ax
		mov		ax, [es:bx+2]
		mov		[bp-2], ax

		; Rotate [bp-4] right by 7 bits:
		lea		bx, [bp-4]
		lea		dx, [bp-4]
		mov		cl, 7
		call near	rotate_right_32

		; Load X into [bp-8]:
		mov		bx, [bp-14]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Rotate [bp-8] right by 18 bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		mov		cl, 18
		call near	rotate_right_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; Load X into [bp-8]:
		mov		bx, [bp-14]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Shift [bp-8] right by 3 bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		mov		cl, 3
		call near	shift_right_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; The anser is in [bp-4], stash it:
		mov		bx, [bp-18]
		mov		ax, [bp-4]
		mov		[es:bx], ax
		mov		ax, [bp-2]
		mov		[es:bx+2], ax

		; Restore the data segment register and GPRs:
		mov		ds, di

		pop		di
		pop		dx
		pop		cx
		pop		bx

		; Restore AX and ES:
		pop		ax
		mov		es, ax
		pop		ax

		mov		sp, bp
		pop		bp
		retn


; Perform the lower-case Sigma1(x) function:
;
; The lower-case Sigma1(x) function is defined as follows:
;
;   ROR(X, 17) XOR ROR(X, 19) XOR SHR(X, 10)
;
;
; Inputs:
;
;   DS:BX - Argument X (pointer to a 32-bit little-endian number).
;   DS:DX - Pointer to where the result should be stored.
;
;   Note:  It is permitted to have the pointers point at the same memory
;          locations.
;
; Outputs:
;
;   The memory that DS:DX points to will be modified to contain the result.
;   The values of all GPRs are preserved.
; 
lc_sigma1:	push		bp
		mov		bp, sp

		; Allocate 2 32-bit variables on the stack:
		sub		sp, 8	; [bp-4], [bp-8]

		; Back AX and ES up:
		push		ax	; [bp-10]
		mov		ax, es
		push		ax	; [bp-12]

		push		bx	; [bp-14]
		push		cx	; [bp-16]
		push		dx	; [bp-18]
		push		di	; [bp-20]

		; DI <- DS, ES <- DS, DS <- SS.
		mov		di, ds
		mov		es, di
		mov		ax, ss
		mov		ds, ax

		; Load X into [bp-4]:
		mov		ax, [es:bx]
		mov		[bp-4], ax
		mov		ax, [es:bx+2]
		mov		[bp-2], ax

		; Rotate [bp-4] right by 17 bits:
		lea		bx, [bp-4]
		lea		dx, [bp-4]
		mov		cl, 17
		call near	rotate_right_32

		; Load X into [bp-8]:
		mov		bx, [bp-14]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Rotate [bp-8] right by 19 bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		mov		cl, 19
		call near	rotate_right_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; Load X into [bp-8]:
		mov		bx, [bp-14]
		mov		ax, [es:bx]
		mov		[bp-8], ax
		mov		ax, [es:bx+2]
		mov		[bp-6], ax

		; Shift [bp-8] right by 10 bits:
		lea		bx, [bp-8]
		lea		dx, [bp-8]
		mov		cl, 10
		call near	shift_right_32

		; Let [bp-4] <- [bp-4] ^ [bp-8]
		lea		dx, [bp-4]
		lea		bx, [bp-4]
		lea		cx, [bp-8]
		call near	xor_32_32

		; The anser is in [bp-4], stash it:
		mov		bx, [bp-18]
		mov		ax, [bp-4]
		mov		[es:bx], ax
		mov		ax, [bp-2]
		mov		[es:bx+2], ax

		; Restore the data segment register and GPRs:
		mov		ds, di

		pop		di
		pop		dx
		pop		cx
		pop		bx

		; Restore AX and ES:
		pop		ax
		mov		es, ax
		pop		ax

		mov		sp, bp
		pop		bp
		retn
