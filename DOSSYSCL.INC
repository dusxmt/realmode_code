; Special file handles:
stdin		equ		0x0000
stdout		equ		0x0001
stderr		equ		0x0002
stdaux		equ		0x0003
stdprn		equ		0x0004

; File access values:
file_read_only	equ		0
file_write_only	equ		1
file_read_write	equ		2

; File attribute flags:
fattr_read_only	equ		(1 << 0)
fattr_hidden	equ		(1 << 1)
fattr_sys_file	equ		(1 << 2)
fattr_vol_lbl	equ		(1 << 3)
fattr_subdir	equ		(1 << 4)
fattr_archived	equ		(1 << 5)

; System call wrapper functions:
		extern		dos_syscl_hfopen
		extern		dos_syscl_hfcreate
		extern		dos_syscl_hclose
		extern		dos_syscl_hread
		extern		dos_syscl_hwrite

; Strerror implementation for the above routines:
		extern		dos_syscl_strerror
