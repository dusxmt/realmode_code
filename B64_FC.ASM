		uppercase
		bits		16
		cpu		8086

		; Include support for fortified DOS system calls:
		%include	"dossyscl.inc"

		; Library routines used:
		extern		conv_bin_b64
		extern		conv_b64_bin
		extern		write_str_zterm
		extern		write_dossyscl_error
		extern		str_identity_check
		extern		char_is_space

segment dseg public class=data align=16
help_screen	db		"Usage: b64_fc [OPTIONS] <INPUT FILE> <OUTPUT FILE>", 0Dh, 0Ah
		db		0Dh, 0Ah
		db		"b64_fc is a program used for encoding files into a Base64 representation, as", 0Dh, 0Ah
		db		"well as decoding Base64-encoded files.", 0Dh, 0Ah
		db		0Dh, 0Ah
		db		"Command-line options:", 0Dh, 0Ah
		db		0Dh, 0Ah
		db		"  -e, --encode          Encode the given input file into Base64 (default)", 0Dh, 0Ah
		db		"  -d, --decode          Decode a Base64-encoded file", 0Dh, 0Ah
		db		"  -s, --stdin           Read input data from stdin", 0Dh, 0Ah
		db		"  -c, --stdout          Write output data to stdout", 0Dh, 0Ah
		db		"  -h, --help            Show this help screen and quit", 0Dh, 0Ah
		db		0

welcome_str	db		"b64_fc - Dooshki's Base64 file encoding and decoding utility."
double_nl_str	db		0Dh, 0Ah
newline_str	db		0Dh, 0Ah, 0
dot_newline_str	db		".", 0Dh, 0Ah, 0

encode_lopt_str	db		"encode", 0
decode_lopt_str	db		"decode", 0
stdin_lopt_str	db		"stdin", 0
stdout_lopt_str	db		"stdout", 0
help_lopt_str	db		"help", 0

no_ifile_str	db		"No input file specified.", 0Dh, 0Ah, 0
no_ofile_str	db		"No output file specified.", 0Dh, 0Ah, 0
invalid_opt_str	db		"Invalid comman-line option: -", 0
unexp_arg_str	db		"Unexpected command-line argument: ", 0

usng_stdin_str	db		"Using stdin for data input.", 0Dh, 0Ah, 0
usng_stdout_str	db		"Using stdout for data output.", 0Dh, 0Ah, 0
opening_str	db		"Opening `", 0
opening_if_str	db		"' for reading... ", 0
opening_of_str	db		"' for writing... ", 0
encoding_str	db		0Dh, 0Ah, "Encoding... ", 0
decoding_str	db		0Dh, 0Ah, "Decoding... ", 0
success_str	db		"ok.", 0Dh, 0Ah, 0
done_str	db		"done.", 0Dh, 0Ah, 0
fail_str	db		"failed: ", 0
read_fail_str	db		"reading from the input file failed: ", 0
write_fail_str	db		"writing to the output file failed: ", 0
incompl_wr_str	db		"Incomplete write, probably due to the disk being full.", 0Dh, 0Ah, 0
decode_fail_str	db		"failed: The input data isn't valid Base64 data.", 0Dh, 0Ah, 0

bin_end_index	resw		1
b64_end_index	resw		1

in_file_handle	resw		1
out_file_handle	resw		1
close_in_file	db		0
close_out_file	db		0
operation	db		1	; 0 means do nothing, 1 means encode,
					; 2 means decode.


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


; Process command-line arguments and initialize program state:
;
;
; Inputs:
;
;   Text on the command line.
;
; Outputs:
;
;   This routine prints the welcome message onto the screen if the cmdline
;   arguments were parsed successfully, and informs the user about the status
;   of file utilization.
;
;   It also prints error messages related to invalid usage.
;
;   It also prints the help screen if neccessary, therefore the global
;   show_help variable shall be used by the calling routine solely for
;   determining whether to prematurely close the program and report success.
;
; NOTE:  For the sake of simplicity, this routine doesn't preserve any GPRs.
;
program_init:	push		bp
		mov		bp, sp

		; Given how in DOS, command-line argumetns are provided to the
		; program in a string at most 127 bytes long, for the worst
		; case scenario of a filename occupying the entire string, set
		; aside 127 + 1 (zero termination) bytes for filenames.
		;sub		sp, 128	; [bp-128] - First file name
		;sub		sp, 128	; [bp-256] - Second file name
		;sub		sp, 1	; [bp-257] - First file name preesnt?
		;sub		sp, 1	; [bp-258] - Second file name preesnt?
		;sub		sp, 1	; [bp-259] - stdin desired?
		;sub		sp, 1	; [bp-260] - stdout desired?
		;
		; The max. size of a long command-line option, including the
		; initial dash, shall be 9 + 1 (zero termination):
		;sub		sp, 10	; [bp-270] - Long option buffer
		;sub		sp, 1	; [bp-271] - Did a parsing error occur?
		;sub		sp, 1	; [bp-272] - Unexpected argument?

		; Allocate the above described stack space in a single swoop:
		sub		sp, 272

		; Initialize stack-allocated variables:
		mov		byte [bp-257], 0
		mov		byte [bp-258], 0
		mov		byte [bp-259], 0
		mov		byte [bp-260], 0
		mov		byte [bp-271], 0
		mov		byte [bp-272], 0

		; Save the old ES and access the Program Segment Prefix:
		mov		ax, es
		push		ax
		mov		ax, [cs:PSP]
		mov		es, ax

		; Walk through the bytes of the command-line arguments buffer:
		xor		ch, ch
		mov		cl, [es:80h]
		xor		si, si

.main_loop:	cmp		si, cx
		jnb		.parsing_done
		mov		al, [es:81h+si]
		inc		si

		call near	char_is_space
		jnc		.main_loop

		cmp		al, '-'
		jz		.read_opts
		jmp		.read_fname

.read_opts:	cmp		si, cx
		jnb		.parsing_done
		mov		al, [es:81h+si]
		inc		si

		call near	char_is_space
		jnc		.main_loop

		cmp		al, '-'
		jz		.read_lopt
		cmp		al, 'e'
		jz		.opt_encode
		cmp		al, 'd'
		jz		.opt_decode
		cmp		al, 's'
		jz		.opt_stdin
		cmp		al, 'c'
		jz		.opt_stdout
		cmp		al, 'h'
		jz		.opt_help
		jmp		.opt_invalid


.opt_encode:	mov		byte [operation], 1
		jmp		.read_opts
.lopt_encode:	mov		byte [operation], 1
		jmp		.lopt_done

.opt_decode:	mov		byte [operation], 2
		jmp		.read_opts
.lopt_decode:	mov		byte [operation], 2
		jmp		.lopt_done

.opt_stdin:	mov		byte [bp-259], 1
		jmp		.read_opts
.lopt_stdin:	mov		byte [bp-259], 1
		jmp		.lopt_done

.opt_stdout:	mov		byte [bp-260], 1
		jmp		.read_opts
.lopt_stdout:	mov		byte [bp-260], 1
		jmp		.lopt_done

.opt_help:	mov		byte [operation], 0
		jmp		.read_opts
.lopt_help:	mov		byte [operation], 0
		jmp		.lopt_done

.lopt_done:	pop		ax
		mov		es, ax
		jmp		.main_loop

.opt_invalid:	mov		byte [bp-271], 1
		; Since no files have been opened yet, we can use a file
		; handle variables to temporarily store things in the data
		; segment.
		mov		[in_file_handle], al
		mov		bx, stderr
		mov		dx, invalid_opt_str
		call near	write_str_zterm

		push		cx
		mov		cx, 1
		mov		dx, in_file_handle
		call near	dos_syscl_hwrite

		mov		cx, 2
		mov		dx, newline_str
		call near	dos_syscl_hwrite
		pop		cx
		jmp		.read_opts

.read_lopt:	xor		di, di
		mov		byte [bp-270+di], al
		inc		di

.rlopt_loop:	cmp		si, cx
		jnb		.lopt_loaded
		mov		al, [es:81h+si]
		inc		si

		call near	char_is_space
		jnc		.lopt_loaded

		cmp		di, 9 ; The lopt buffer is 9 + 1 (zterm) long.
		jnb		.lopt_too_long

		mov		[bp-270+di], al
		inc		di
		jmp		.rlopt_loop

.lopt_loaded:	mov		byte [bp-270+di], 0
		lea		bx, [bp-270+1]	; +1 for the initial dash.
		mov		ax, es
		push		ax
		mov		ax, ss
		mov		es, ax		; es:bx is now the loaded lopt.

		mov		dx, encode_lopt_str
		call near	str_identity_check
		jnc		.lopt_encode

		mov		dx, decode_lopt_str
		call near	str_identity_check
		jnc		.lopt_decode

		mov		dx, stdin_lopt_str
		call near	str_identity_check
		jnc		.lopt_stdin

		mov		dx, stdout_lopt_str
		call near	str_identity_check
		jnc		.lopt_stdout

		mov		dx, help_lopt_str
		call near	str_identity_check
		jnc		.lopt_help

		pop		ax
		mov		es, ax
		jmp		.lopt_invalid


.lopt_too_long:	mov		byte [bp-270+di], 0
.deplete_loop:	cmp		si, cx
		jnb		.deplete_complete
		mov		al, [es:81h+si]
		inc		si

		call near	char_is_space
		jnc		.deplete_complete

		jmp		.deplete_loop
.deplete_complete:

.lopt_invalid:	mov		bx, stderr
		mov		dx, invalid_opt_str
		call near	write_str_zterm

		mov		ax, ds
		push		ax
		mov		ax, ss
		mov		ds, ax
		lea		dx, [bp-270]
		call near	write_str_zterm
		pop		ax
		mov		ds, ax

		mov		dx, newline_str
		call near	write_str_zterm

		mov		byte [bp-271], 1
		jmp		.main_loop

.read_fname:	cmp		byte [bp-257], 0	; Input file known?
		jnz		.have_file1
		cmp		byte [bp-259], 0	; stdin desired?
		jnz		.have_file1

		mov		byte [bp-257], 1
		lea		bx, [bp-128]
		jmp		.load_fname

.have_file1:	cmp		byte [bp-258], 0	; Output file known?
		jnz		.have_file2
		cmp		byte [bp-260], 0	; stdout desired?
		jnz		.have_file2

		mov		byte [bp-258], 1
		lea		bx, [bp-256]
		jmp		.load_fname

		; Unexpected argument?  Well, since we'll error out, we won't
		; end up opening any files, so we might as well load this
		; unexpected argument into the output file name buffer, so that
		; we can print it in an error message.
.have_file2:	mov		byte [bp-272], 1
		lea		bx, [bp-256]

.load_fname:	mov		[ss:bx], al
		inc		bx
.fnload_loop:	cmp		si, cx
		jnb		.fname_loaded
		mov		al, [es:81h+si]
		inc		si

		call near	char_is_space
		jnc		.fname_loaded

		mov		[ss:bx], al
		inc		bx
		jmp		.fnload_loop


.fname_loaded:	mov		byte [ss:bx], 0
		; Sure, we've loaded something, but do we want it?
		cmp		byte [bp-272], 0
		jz		.main_loop

		mov		bx, stderr
		mov		dx, unexp_arg_str
		call near	write_str_zterm

		mov		ax, ds
		push		ax
		mov		ax, ss
		mov		ds, ax
		lea		dx, [bp-256]
		call near	write_str_zterm

		pop		ax
		mov		ds, ax

		mov		dx, newline_str
		call near	write_str_zterm

		mov		byte [bp-271], 1
		jmp		.main_loop

.parsing_done:	cmp		byte [bp-271], 0
		jz		.parsing_ok

.err_showhelp:	mov		byte [operation], 0

		mov		bx, stderr
		mov		dx, help_screen
		call near	write_str_zterm

		; The input file might be open if we failed to open the
		; output file.
.err_nohelp:	call near	close_files
.err_noiclose:	clc
		cmc
		jmp		.epilogue


.parsing_ok:	cmp		byte [operation], 0
		jz		.show_help

		; Sanity check:
		cmp		byte [bp-257], 0	; Input file known?
		jnz		.have_ifile
		cmp		byte [bp-259], 0	; stdin desired?
		jnz		.have_ifile

		mov		bx, stderr
		mov		dx, no_ifile_str
		call near	write_str_zterm
		mov		byte [bp-271], 1

.have_ifile:	cmp		byte [bp-258], 0	; Output file known?
		jnz		.have_ofile
		cmp		byte [bp-260], 0	; stdout desired?
		jnz		.have_ofile

		mov		bx, stderr
		mov		dx, no_ofile_str
		call near	write_str_zterm
		mov		byte [bp-271], 1

.have_ofile:	cmp		byte [bp-271], 0
		jnz		.err_showhelp

		; Now that we've reached this point, we can show the program's
		; welcome message:
		mov		bx, stderr
		mov		dx, welcome_str
		call near	write_str_zterm

		; Since we'll be switching between segments, have them ready.
		mov		si, ss
		mov		di, ds

.ready_ifile:	cmp		byte [bp-259], 0	; stdin desired?
		jz		.open_ifile

		mov		dx, usng_stdin_str
		call near	write_str_zterm
		mov		word [in_file_handle], stdin
		mov		byte [close_in_file], 0
		jmp		.ready_ofile

.open_ifile:	mov		dx, opening_str
		call near	write_str_zterm

		mov		ds, si
		lea		dx, [bp-128]
		call near	write_str_zterm

		mov		ds, di
		mov		dx, opening_if_str
		call near	write_str_zterm

		mov		ds, si
		lea		dx, [bp-128]
		mov		al, file_read_only
		call near	dos_syscl_hfopen
		mov		ds, di
		jnc		.ifopen_ok

		mov		cx, ax
		mov		dx, fail_str
		call near	write_str_zterm

		mov		ax, cx
		call near	write_dossyscl_error
		jmp		.err_nohelp

.ifopen_ok:	mov		[in_file_handle], ax
		mov		byte [close_in_file], 1

		mov		dx, success_str
		call near	write_str_zterm

.ready_ofile:	cmp		byte [bp-260], 0	; stdout desired?
		jz		.open_ofile

		mov		dx, usng_stdout_str
		call near	write_str_zterm
		mov		word [out_file_handle], stdout
		mov		byte [close_out_file], 0
		jmp		.all_done

.open_ofile:	mov		dx, opening_str
		call near	write_str_zterm

		mov		ds, si
		lea		dx, [bp-256]
		call near	write_str_zterm

		mov		ds, di
		mov		dx, opening_of_str
		call near	write_str_zterm

		mov		ds, si
		lea		dx, [bp-256]
		xor		cx, cx
		call near	dos_syscl_hfcreate
		mov		ds, di
		jnc		.ofopen_ok

		mov		cx, ax
		mov		dx, fail_str
		call near	write_str_zterm

		mov		ax, cx
		call near	write_dossyscl_error
		jmp		.err_nohelp

.ofopen_ok:	mov		[out_file_handle], ax
		mov		byte [close_out_file], 1

		mov		dx, success_str
		call near	write_str_zterm

.all_done:	clc
		jmp		.epilogue
		
.show_help:	mov		bx, stdout
		mov		dx, help_screen
		call near	write_str_zterm
		clc

.epilogue:	pop		ax
		mov		es, ax
		mov		sp, bp
		pop		bp
		retn


; Close open files:
;
; Inputs:
;
;   Program state within the data segment.
;
; Outputs:
;
;   None.
;
; The values of all GPRs are preserved.
; 
close_files:	push		ax
		push		bx

		cmp		byte [close_in_file], 0
		jz		.no_close_in
		mov		bx, [in_file_handle]
		call near	dos_syscl_hclose

		mov		byte [close_in_file], 0
		mov		word [in_file_handle], 0
.no_close_in:
		cmp		byte [close_out_file], 0
		jz		.no_close_out
		mov		bx, [out_file_handle]
		call near	dos_syscl_hclose

		mov		byte [close_out_file], 0
		mov		word [out_file_handle], 0
.no_close_out:
		pop		bx
		pop		ax
		retn


; The main routine of the program:
;
main:		call near	program_init
		jnc		.init_ok

		; If we failed to initialize, return a non-zero exit status.
		mov		al, 1
		retn

.init_ok:	cmp		byte [operation], 0
		jnz		.check_op

		; Only printed a help screen?  In that case, we're done here.
		xor		al, al
		retn

		; Determine which operation to perform:
.check_op:	cmp		byte [operation], 1
		jnz		.perform_dec


		; Encode the input file:
.perform_enc:	mov		bx, stderr
		mov		dx, encoding_str
		call		write_str_zterm

		mov		si, bin_buf_seg
		mov		di, b64_buf_seg

		mov		ax, ds
		push		ax
		mov		es, ax

.enc_loop:	mov		ds, si
		mov		bx, [es:in_file_handle]
		mov		cx, 48 * 1024
		xor		dx, dx
		call near	dos_syscl_hread
		jc		.read_failed
		test		ax, ax
		jz		.done

		mov		cx, ax
		dec		cx
		mov		bx, si
		mov		dx, di
		pop		ax
		mov		ds, ax
		push		ax
		call near	conv_bin_b64

		mov		bx, [es:out_file_handle]
		mov		ds, di
		xor		dx, dx
		cmp		cx, 0FFFFh
		jz		.split_write

		inc		cx
		call near	dos_syscl_hwrite
		jc		.write_failed
		cmp		ax, cx
		jnz		.write_short

		jmp		.enc_loop

		; We have 64K of bytes to write, that's 1 byte more than
		; the DOS "handle" write routine can handle; let's split
		; it into two 32K writes.
.split_write:	mov		cx, 32 * 1024
		call near	dos_syscl_hwrite
		jc		.write_failed
		cmp		ax, cx
		jnz		.write_short

		mov		dx, cx
		call near	dos_syscl_hwrite
		jc		.write_failed
		cmp		ax, cx
		jnz		.write_short

		jmp		.enc_loop


		; Decode the input file:
.perform_dec:	mov		bx, stderr
		mov		dx, decoding_str
		call		write_str_zterm

		mov		si, b64_buf_seg
		mov		di, bin_buf_seg

		mov		ax, ds
		push		ax
		mov		es, ax

		; Since the Base64 buffer is 64K long, which is 1 byte more
		; than the DOS "handle" read routine can handle, fill it using
		; two 32K reads:
.dec_loop:	mov		ds, si
		xor		dx, dx
		mov		bx, [es:in_file_handle]
		mov		cx, 32 * 1024
		call near	dos_syscl_hread
		jc		.read_failed
		test		ax, ax
		jz		.done

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
		mov		cx, ax
		dec		cx
		mov		bx, si
		mov		dx, di
		pop		ax
		mov		ds, ax
		push		ax
		call near	conv_b64_bin
		jc		.dec_failed

		mov		bx, [es:out_file_handle]
		mov		ds, di
		xor		dx, dx
		inc		cx
		call near	dos_syscl_hwrite
		jc		.write_failed
		cmp		ax, cx
		jnz		.write_short

		jmp		.dec_loop


.read_failed:	mov		di, ax

		pop		ax
		mov		ds, ax

		mov		bx, stderr
		mov		dx, read_fail_str
		call near	write_str_zterm

		mov		ax, di
		call near	write_dossyscl_error

		call near	close_files
		mov		al, 2
		retn

.dec_failed:	pop		ax
		mov		ds, ax

		mov		bx, stderr
		mov		dx, decode_fail_str
		call near	write_str_zterm

		call near	close_files
		mov		al, 3
		retn

.write_failed:	mov		di, ax

		pop		ax
		mov		ds, ax

		mov		bx, stderr
		mov		dx, write_fail_str
		call near	write_str_zterm

		mov		ax, di
		call near	write_dossyscl_error

		call near	close_files
		mov		al, 2
		retn

.write_short:	pop		ax
		mov		ds, ax

		mov		bx, stderr
		mov		dx, write_fail_str
		call near	write_str_zterm

		mov		dx, incompl_wr_str
		call near	write_str_zterm

		call near	close_files
		mov		al, 2
		retn


.done:		pop		ax
		mov		ds, ax

		mov		bx, stderr
		mov		dx, done_str
		call near	write_str_zterm

		call near	close_files
		xor		al, al
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
