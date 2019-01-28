		uppercase
		bits		16
		cpu		8086

; Fortified DOS System Call Interface module.
;
; The purpose of this module is to provide a well-defined interface to the 21h
; MS-DOS system call interface.	
;
; While Microsoft does claim that the MS-DOS system call routines preserve all
; general purpose registers that are not used as return values, it is not 100%
; certain whether this applies to all versions of DOS, and therefore, this
; module provides wrappers to the system calls that make sure to preserve all
; general purpose registers that are not used as return values.
;
; The idea is to prevent subtle and hard-to-reproduce errors when running code
; on various DOS machines if it turns out that certain versions of DOS violate
; our assumptions of the state of the register file.
;
; In addition, descriptions for some DOS error codes are provided.
;

segment dseg public class=data
err00_str	db		"No error", 0
err01_str	db		"Invalid function", 0
err02_str	db		"File not found", 0
err03_str	db		"Path not found", 0
err04_str	db		"Too many open files", 0
err05_str	db		"Access denied", 0
err06_str	db		"Invalid file handle", 0
err07_str	db		"Memory control blocks destroyed", 0
err08_str	db		"Insufficient memory", 0
err09_str	db		"Invalid memory block address", 0
err10_str	db		"Invalid environment", 0
err11_str	db		"Invalid format", 0
err12_str	db		"Invalid access", 0
err13_str	db		"Invalid data", 0
err15_str	db		"Invalid drive specified", 0
err16_str	db		"Removal of current directory attempted", 0
err17_str	db		"Devices do not match", 0
err18_str	db		"No more files", 0
err_unknown	db		"Unknown error", 0

err_tbl		dw		 err00_str, err01_str, err02_str, err03_str
		dw		 err04_str, err05_str, err06_str, err07_str
		dw		 err08_str, err09_str, err10_str, err11_str
		dw		 err12_str, err13_str, err_unknown, err15_str
		dw		 err16_str, err17_str, err18_str

known_errors	equ		19


segment cseg public class=code align=16

; Get a string to describe error code:
;
; Certain DOS system calls return an error code in AX, this routine assigns
; a zero-terminated string to the most commmon error codes.
;
; Inputs:
;
;   AX - Error code
;
; Outputs:
;
;   DX - Offset within this module's data segment to the appropriate string.
;
; All other GPRs are preserved.
;
		global		dos_syscl_strerror
dos_syscl_strerror:
		cmp		ax, known_errors
		jnb		.unknown_err

		push		di
		mov		di, ax
		shl		di, 1
		mov		dx, [err_tbl+di]
		pop		di
		retn

.unknown_err:	mov		dx, err_unknown
		retn


; Open an existing file, using the handle interface (int 21h, AH=3Dh):
;
; Inputs:
;
;   AL    - File access value (see dossyscl.inc for possible values).
;   DS:DX - Zero-terminated file name string.
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set:   Error code.
;              - If CF is clear: File handle value.
;
; All other GPRs are preserved.
;
		global		dos_syscl_hfopen
dos_syscl_hfopen:
		mov		ah, 3Dh
		jmp		ax_retval_syscall


; Create a new file, using the handle interface (int 21h, AH=3Ch):
;
; The newly created file will be open for writing only.  If the file already
; exists, it will be truncated.
;
;
; Inputs:
;
;   CX    - File attribute value (see dossyscl.inc for possible values).
;   DS:DX - Zero-terminated file name string.
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set:   Error code.
;              - If CF is clear: File handle value.
;
; All other GPRs are preserved.
;
		global		dos_syscl_hfcreate
dos_syscl_hfcreate:
		mov		ah, 3Ch
		jmp		ax_retval_syscall


; Close the provided file handle (int 21h, AH=3Eh):
;
; Inputs:
;
;   BX - File handle.
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set:   Error code.
;              - If CF is clear: Undefined.
;
; All other GPRs are preserved.
;
		global		dos_syscl_hclose
dos_syscl_hclose:
		mov		ah, 3Eh
		jmp		ax_retval_syscall


; Read from a file, using the handle interface (int 21h, AH=3Fh):
;
; Inputs:
;
;   BX    - File handle.
;   CX    - Number of bytes to read.
;   DS:DX - Start of the buffer where the read data should be stored.
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set:   Error code.
;              - If CF is clear: Number of bytes read from the file.
;
; All other GPRs are preserved.
;
		global		dos_syscl_hread
dos_syscl_hread:
		mov		ah, 3Fh
		jmp		ax_retval_syscall


; Write to a file, using the handle interface (int 21h, AH=40h):
;
; Inputs:
;
;   BX    - File handle.
;   CX    - Number of bytes to write.
;   DS:DX - Location of the start of the data to write.
;
; Outputs:
;
;   Carry flag - Set on error conditions, clear on success.
;
;   AX         - If CF is set:   Error code.
;              - If CF is clear: Number of bytes written to the file.
;
; All other GPRs are preserved.
;
		global		dos_syscl_hwrite
dos_syscl_hwrite:
		mov		ah, 40h
		jmp		ax_retval_syscall


; AX Return Value System Call wrapper:
;
; Perform a DOS `int 21h' system call, preserving all GPRs except for AX.
;
ax_retval_syscall:
		push		bx
		push		cx
		push		dx
		push		si
		push		di
		push		bp

		int		21h

		pop		bp
		pop		di
		pop		si
		pop		dx
		pop		cx
		pop		bx
		retn
