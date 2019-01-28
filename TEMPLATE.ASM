		uppercase
		bits		16
		cpu		8086

segment dseg public class=data align=16
; Place global vars here.


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
main:		xor		al, al
		retn


segment sseg stack class=stack align=16
		resb		2048
stack_top:
