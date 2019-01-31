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
; buffer is valid for as long as no routine provided by this module is invoked.
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
bytes_in_m:	resb		1

; Work variables for sha256_hash_chunk:
work_var_1:	resd		1
work_var_2:	resd		1
work_var_3:	resd		1
work_var_4:	resd		1

letter_work_vars:
work_var_a:	resd		1
work_var_b:	resd		1
work_var_c:	resd		1
work_var_d:	resd		1
work_var_e:	resd		1
work_var_f:	resd		1
work_var_g:	resd		1
work_var_h:	resd		1

work_var_temp1:	resd		1
work_var_temp2:	resd		1


segment cseg public class=code align=16

; Initialize the internal state of the module, and prepare it for receiving
; data to hash.
;
; Inputs:
;
;   DS has to be set to the data segment of this module.
;
; Outputs: None.
;
; The values of all GPRs are preserved.
;
		global		sha256_init
sha256_init:	push		ax
		push		cx
		push		si
		push		di

		; Initialize the hash:
		mov		si, hash_init
		mov		di, hash_current
		mov		cx, si
		add		cx, 8 * 4

.hinit_loop:	mov		ax, [si]
		mov		[di], ax
		add		si, 2
		add		di, 2
		cmp		si, cx
		jb		.hinit_loop

		; Initialize the message length:
		xor		ax, ax
		mov		word [message_bits], ax
		mov		word [message_bits+2], ax
		mov		word [message_bits+4], ax
		mov		word [message_bits+6], ax

		; Initialize the message chunk buffer:
		mov		byte [bytes_in_m], al

		pop		di
		pop		si
		pop		cx
		pop		ax
		retn


; Process the provided data buffer:
;
; This routine takes the provided buffer of data, fills the message buffer
; with it, and upon each fill of 64 bytes it iterates thorugh the hashing
; process.
;
; The routine itself merely loads the individual bytes of the message and
; uses sha256_hash_byte to place them into the message buffer and process them.
;
;
; Inputs:
;
;   DS has to be set to the data segment of this module.
;
;   ES:BX - Pointer to the first byte of the message chunk to hash.
;   ES:DX - Pointer to the last byte of the message chunk to hash.
;
;   Note:  The reason for the use of a start and end index is to allow the use
;          of a full 64K-sized buffer (a 16-bit size variable can describe
;          a buffer at most 65535 large, which is 1 byte less than a full 64K).
;
; Outputs: None.
;
; The values of all GPRs are preserved.
;
		global		sha256_hash_data
sha256_hash_data:
		push		ax
		push		bx

.load_loop:	mov		al, [es:bx]
		call near	sha256_hash_byte
		cmp		bx, dx
		jz		.done
		inc		bx
		jmp		.load_loop
		
.done:		pop		bx
		pop		ax
		retn


; Add the provided byte into the message buffer:
;
;
; This routine loads the provided byte into the message buffer.  The bytes are
; interpreted as the intividual quarters of 32-bit big-endian words; the most
; significant byte comes first and the least significant byte comes last.
;
; To achieve this ordering (given that the 8086 is a little-endian platform),
; the two lowest bits of the index of the byte within the message buffer are
; inverted, which causes the load order to be:
;
;   3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, etc.
;
; Upon loading 512 bits (64 bytes, 16 32-bit values), the message is processed,
; the registered message length is bumped up by 512, and the current hash value
; is updated.
;
;
; Inputs:
;
;   DS has to be set to the data segment of this module.
;   AL - byte to add to the message buffer.
;
; Outputs: None.
;
; The values of all GPRs are preserved.
;
		global		sha256_hash_byte
sha256_hash_byte:
		push		ax
		push		bx

		mov		bl, [bytes_in_m]
		xor		bh, bh

		; By inverting the two LSBs of the current byte count, we get
		; the index of where to load the byte into the message buffer.
		mov		ah, bl
		not		ah
		and		ah, 03h
		and		bl, 0FCh
		or		bl, ah

		mov		[m_array+bx], al

		mov		al, [bytes_in_m]
		inc		al
		mov		[bytes_in_m], al

		cmp		al, 64
		jb		.skip_hash
		call near	sha256_hash_chunk
.skip_hash:
		pop		bx
		pop		ax
		retn


; Process an entire message chunk:
;
; In addition to performing the mathematical operations neccessary to calculate
; the current intermediate hash value, this routine updates the message length
; by incrementing the variable tracking it by 512 bits, which is the length of
; a message chunk.
;
; You must manually subtract away processed padding bits from or add yet
; un-processed message bits to the message length variable when producing the
; last couple of message chunks in the sha256_finish routine.
;
;
; Inputs:
;
;   DS has to be set to the data segment of this module.
;   The data in the message chunk buffer is processed.
;
; Outputs:
;
;   The hash gets updated.
;
; The values of all GPRs are preserved.
;
sha256_hash_chunk:
		push		ax
		push		bx
		push		cx
		push		dx
		push		di
		push		si

		; Do some book-keeping:
		mov		cx, 512
		mov		dx, message_bits
		call near	add_64_16
		mov		byte [bytes_in_m], 0


		; Initialize the SHA-256 message schedule:
		;
		; The first 16 entries are a copy of the message buffer:
		;
		mov		si, m_array
		mov		di, w_array
		mov		cx, di
		add		cx, 16 * 4

.w16_loop:	mov		ax, [si]
		mov		[di], ax
		add		si, 2
		add		di, 2
		cmp		di, cx
		jnz		.w16_loop

		; As for w[16..63], they're defined as:
		;
		; w[j] <- lc_sgm0(w[j-15]) + lc_sgm1(w[j-2]) + w[j-7] + w[j-16]
		;
		mov		dx, di		; DX represents j (now 16)
		add		di, 48 * 4	; DI represents 64

		; Let w[j] <- w[j-16]:
.w64_loop:	mov		si, dx
		mov		bx, dx		; BX represents j
		sub		si, 16 * 4	; SI represents j-16

		mov		ax, [si]
		mov		[bx], ax
		mov		ax, [si+2]
		mov		[bx+2], ax

		; Let w[j] <- w[j] + w[j-7]:
		add		si, 9 * 4	; SI represents j-7
		mov		bx, dx		; Both BX and DX represent j
		mov		cx, si		; CX represents j-7
		call near	add_modulo_2_32

		; Let work_var_1 <- lc_sgm0(w[j-15]):
		sub		si, 8 * 4	; SI represents j-15
		push		dx
		mov		dx, work_var_1
		mov		bx, si
		call near	sha_func_lc_sigma0

		; Let work_var_2 <- lc_sgm1(w[j-2]):
		add		bx, 13 * 4	; BX represents j-2
		mov		dx, work_var_2
		call near	sha_func_lc_sigma1

		; Let w[j] <- w[j] + work_var_2:
		mov		cx, dx
		pop		dx		; DX represents j
		mov		bx, dx		; Both BX and DX represent j
		call near	add_modulo_2_32

		; Let w[j] <- w[j] + work_var_1:
		mov		cx, work_var_1
		call near	add_modulo_2_32

		; Let j <- (j + 1):
		add		dx, 4
		
		cmp		dx, di
		jb		.w64_loop

		; Initialize the a..f work wariables (to be the current hash):
		mov		si, hash_current
		mov		di, letter_work_vars
		mov		cx, di
		add		cx, 8 * 4

.lww_init_loop:	mov		ax, [si]
		mov		[di], ax
		add		si, 2
		add		di, 2
		cmp		di, cx
		jnz		.lww_init_loop

		; Compression function main loop:
		xor		di, di		; j <- 0.

.cf_main_loop:	; Let work_var_1 <- Ch(e, f, g):
		mov		bx, work_var_e
		mov		cx, work_var_f
		mov		si, work_var_g
		mov		dx, work_var_1
		call near	sha_func_ch_xyz

		; Let work_var_2 <- Maj(a, b, c):
		mov		bx, work_var_a
		mov		cx, work_var_b
		mov		si, work_var_c
		mov		dx, work_var_2
		call near	sha_func_maj_xyz

		; Let work_var_3 <- uc_sgm0(a):
		mov		dx, work_var_3
		call near	sha_func_uc_sigma0

		; Let work_var_4 <- uc_sgm1(e):
		mov		bx, work_var_e
		mov		dx, work_var_4
		call near	sha_func_uc_sigma1

		; Let temp1 <- k[j] + w[j]:
		lea		bx, [di+k_table]
		lea		cx, [di+w_array]
		mov		dx, work_var_temp1
		call near	add_modulo_2_32

		; Let temp1 <- temp1 + h:
		mov		bx, dx
		mov		cx, work_var_h
		call near	add_modulo_2_32

		; Let temp1 <- temp1 + uc_sgm1(e):
		mov		cx, work_var_4
		call near	add_modulo_2_32

		; Let temp1 <- temp1 + Ch(e, f, g):
		mov		cx, work_var_1
		call near	add_modulo_2_32

		; Let temp2 <- uc_sgm0(a) + Maj(a, b, c):
		mov		bx, work_var_3
		mov		cx, work_var_2
		mov		dx, work_var_temp2
		call near	add_modulo_2_32

		; Let h <- g:
		mov		si, work_var_g
		mov		bx, work_var_h
		mov		ax, [si]
		mov		[bx], ax
		mov		ax, [si+2]
		mov		[bx+2], ax

		; Let g <- f:
		mov		si, work_var_f
		mov		bx, work_var_g
		mov		ax, [si]
		mov		[bx], ax
		mov		ax, [si+2]
		mov		[bx+2], ax

		; Let f <- e:
		mov		si, work_var_e
		mov		bx, work_var_f
		mov		ax, [si]
		mov		[bx], ax
		mov		ax, [si+2]
		mov		[bx+2], ax

		; Let e <- d:
		mov		si, work_var_d
		mov		bx, work_var_e
		mov		ax, [si]
		mov		[bx], ax
		mov		ax, [si+2]
		mov		[bx+2], ax

		; Let e <- e + temp1
		mov		dx, bx
		mov		cx, work_var_temp1
		call near	add_modulo_2_32

		; Let d <- c:
		mov		si, work_var_c
		mov		bx, work_var_d
		mov		ax, [si]
		mov		[bx], ax
		mov		ax, [si+2]
		mov		[bx+2], ax

		; Let c <- b:
		mov		si, work_var_b
		mov		bx, work_var_c
		mov		ax, [si]
		mov		[bx], ax
		mov		ax, [si+2]
		mov		[bx+2], ax

		; Let b <- a:
		mov		si, work_var_a
		mov		bx, work_var_b
		mov		ax, [si]
		mov		[bx], ax
		mov		ax, [si+2]
		mov		[bx+2], ax

		; Let a <- temp1 + temp2
		mov		bx, work_var_temp1
		mov		cx, work_var_temp2
		mov		dx, work_var_a
		call near	add_modulo_2_32

		; Let j <- (j + 1)
		add		di, 4

		cmp		di, 64 * 4
		jb		.cf_main_loop

		; Compute the current intermediate value of the hash:
		xor		si, si		; j <- 0.
		mov		di, 8 * 4

.hc_loop:	lea		bx, [hash_current+si]
		lea		cx, [letter_work_vars+si]
		mov		dx, bx
		call near	add_modulo_2_32

		add		si, 4		; j <- (j + 1)
		cmp		si, di
		jb		.hc_loop

		pop		si
		pop		di
		pop		dx
		pop		cx
		pop		bx
		pop		ax
		retn


; Terminate the message and reorder the hash bytes into big-endian:
;
; Inputs:
;
;   DS has to be set to the data segment of this module.
;
; Outputs:
;
;   DS:DX - pointer to the hash buffer.
;
; The values of all other GPRs are preserved.
;
		global		sha256_finish
sha256_finish:	push		bp
		mov		bp, sp

		; Allocate space on the stack for the message length:
		sub		sp, 8	; [bp-8]

		push		ax	; [bp-10]
		push		bx	; [bp-12]
		push		cx	; [bp-14]
		push		si	; [bp-16]

		; Save the current message length and update it to contain
		; the message bits that weren't yet hashed:
		mov		ax, [message_bits]
		mov		[bp-8], ax
		mov		ax, [message_bits+2]
		mov		[bp-6], ax
		mov		ax, [message_bits+4]
		mov		[bp-4], ax
		mov		ax, [message_bits+6]
		mov		[bp-2], ax

		mov		cl, [bytes_in_m]
		xor		ch, ch
		test		cx, cx
		jz		.skip_add_cx

		mov		si, ds
		mov		ax, ss
		mov		ds, ax

		lea		dx, [bp-8]
		shl		cx, 1	; Shifting only a single bit at a time
		shl		cx, 1	; for the sake of 8086 compatibility.
		shl		cx, 1
		call near	add_64_16
		shr		cx, 1
		shr		cx, 1
		shr		cx, 1
		mov		ds, si
.skip_add_cx:
		; Can we fit 9 bytes (message termination and length) into
		; the current message chunk?
		cmp		cx, 64 - 9
		jbe		.can_fit

		; Finish off the current chunk then:
		mov		al, 80h
		call near	sha256_hash_byte
		inc		cx

		xor		al, al
.pad_loop1:	cmp		cx, 64
		jz		.pl1_done

		call near	sha256_hash_byte
		inc		cx
		jmp		.pad_loop1
.pl1_done:	xor		cx, cx
		jmp		.pad_loop2


.can_fit:	mov		al, 80h
		call near	sha256_hash_byte
		inc		cx

		xor		al, al
.pad_loop2:	cmp		cx, 64 - 8
		jz		.pl2_done

		call near	sha256_hash_byte
		inc		cx
		jmp		.pad_loop2
.pl2_done:	
		; Hash the message length, load it in in big-endian order:
		mov		al, [bp-1]
		call near	sha256_hash_byte
		mov		al, [bp-2]
		call near	sha256_hash_byte
		mov		al, [bp-3]
		call near	sha256_hash_byte
		mov		al, [bp-4]
		call near	sha256_hash_byte
		mov		al, [bp-5]
		call near	sha256_hash_byte
		mov		al, [bp-6]
		call near	sha256_hash_byte
		mov		al, [bp-7]
		call near	sha256_hash_byte
		mov		al, [bp-8]
		call near	sha256_hash_byte

		; The hash is now ready, now we just need to reverse the bytes
		; of the 32-bit words so that they're in big-endian format:
		;
		mov		si, hash_current
		mov		cx, si
		add		cx, 8 * 4

.bswap_loop:	mov		ax, [si]
		mov		dx, [si+2]
		xchg		al, ah
		xchg		dl, dh
		mov		[si+2], ax
		mov		[si], dx

		add		si, 4
		cmp		si, cx
		jb		.bswap_loop

		mov		dx, hash_current

		pop		si
		pop		cx
		pop		bx
		pop		ax

		mov		sp, bp
		pop		bp
		retn


; The numeric functions that are used by SHA256:
;

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
sha_func_ch_xyz:
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
sha_func_maj_xyz:
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
sha_func_uc_sigma0:
		push		bp
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
sha_func_uc_sigma1:
		push		bp
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
sha_func_lc_sigma0:
		push		bp
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
sha_func_lc_sigma1:
		push		bp
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


; The message length in bits is 64-bit, and the message chunk size is 512 bits,
; so the following routine should be sufficient for maintaining the message
; length variable: 

; Add a 16-bit number to a 64-bit number:
;
; The purpose of this routine is to add the number of processed bits to the
; variable tracking the length of the message.
;
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


; Basic operations on 32-bit little-endinan numbers:
;

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
