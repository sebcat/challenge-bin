;;; 
;;; sect2014.asm - a binary for the SEC-T challenge
;;; Platform: freebsd/amd64
;;; build: nasm -fbin -osect2014 sect2014.asm
;;; Sebastian Cato, Sept 2014
;;;

BITS 64

;; ELF stuff from: 
;; /usr/include/sys/elf_common.h, /usr/include/sys/elf64.h

;;
;; ELF file header
;;
%define 	ELFCLASS64		2
%define		ELFDATA2LSB		1
%define		EV_CURRENT		1
%define 	ELFOSABI_LINUX 		3
%define 	ELFOSABI_FREEBSD	9

%define 	ET_EXEC			2
%define		EM_X86_64		62

%define		BASEADDR		0x400000

begin_ehdr:
;; unsigned char   e_ident[EI_NIDENT];     /* File identification. */
	;; e_ident, e_ident+3 : magic \x7fELF
	db	0x7f, 'E', 'L', 'F'

	;; e_ident+4: EI_CLASS
	db	ELFCLASS64

	;; e_ident+5: EI_DATA
	db	ELFDATA2LSB

	;; e_ident+6: EI_VERSION
	db	EV_CURRENT	

	;; e_ident+7: EI_OSABI
	db	ELFOSABI_FREEBSD
	
	;; e_ident+8: EI_ABIVERSION
	db	0
	
	;; e_ident+9, e_ident+15: padding
	;; so it turns out some elf loaders are quite picky about the padding
	;;db 	0, 's', 'e', 'c', '-', 't', 0	
	db 	0, 0, 0, 0, 0, 0, 0

;;        Elf64_Half      e_type;       /* File type. */
	dw	ET_EXEC

;;        Elf64_Half      e_machine;   /* Machine architecture. */
	dw	EM_X86_64
	
;;        Elf64_Word      e_version;   /* ELF format version. */
	dd	EV_CURRENT

;;        Elf64_Addr      e_entry;     /* Entry point. */
	dq	BASEADDR + (begin_seg0-begin_ehdr)

;;        Elf64_Off       e_phoff;     /* Program header file offset. */
	dq	begin_phdr-begin_ehdr

;;        Elf64_Off       e_shoff;     /* Section header file offset. */
	dq	0	

;;        Elf64_Word      e_flags;     /* Architecture-specific flags. */
	dd	0

;;        Elf64_Half      e_ehsize;    /* Size of ELF header in bytes. */
	dw	ehdrlen

;;        Elf64_Half      e_phentsize; /* Size of program header entry. */
	dw	phentsize

;;        Elf64_Half      e_phnum;     /* Number of program header entries. */
	dw	1

;;        Elf64_Half      e_shentsize; /* Size of section header entry. */
	dw	0	

;;        Elf64_Half      e_shnum;     /* Number of section header entries. */
	dw	0

;;        Elf64_Half      e_shstrndx;  /* Section name strings section. */
	dw	0
ehdrlen	equ $-begin_ehdr
	


;;
;; ELF program header table
;;
%define		PT_LOAD		1
%define		PF_X		0x01
%define		PF_W		0x02
%define		PF_R		0x04
begin_phdr:
;;        Elf64_Word      p_type;       /* Entry type. */
	dd	PT_LOAD

;;        Elf64_Word      p_flags;      /* Access permission flags. */
	dd	PF_R | PF_W | PF_X	

;;        Elf64_Off       p_offset;     /* File offset of contents. */
	dq	0

;;        Elf64_Addr      p_vaddr;      /* Virtual address in memory image. */
	dq	BASEADDR

;;        Elf64_Addr      p_paddr;      /* Physical address (not used). */
	dq	0 

;;        Elf64_Xword     p_filesz;     /* Size of contents in file. */
	dq	end_seg0-begin_ehdr

;;        Elf64_Xword     p_memsz;      /* Size of contents in memory. */
	dq	end_seg0-begin_ehdr

;;        Elf64_Xword     p_align;      /* Alignment in memory and file. */
	dq	16
phentsize equ $-begin_phdr

;;
;; ELF segment 0
;;

%define 	SYS_exit	1
%define		SYS_write	4

%define 	STDOUT_FILENO	1

	align 16
begin_seg0:
	;; get address of argc to rdi
	;; the normal way to get the address to argc+argv is from rdi, as shown:
	;; see https://github.com/sebcat/nolibs-stub/blob/master/entry.asm#L8-L10
	;; but why not get it from rsp directly to confuse people...
	mov	rdi, rsp
	mov	rax, [rdi]
	test	rax, rax
	jnz	.got_argc_addr
	add	rdi, 8
.got_argc_addr:
	mov 	rax, [rdi]
	cmp	al, 2
	jz	.correct_argc
	xor	rdi, rdi
	inc	rdi
	call	exit
.correct_argc:
	mov	rsi, [rdi+16] ; argv[1]

;; FNV1a hash argv[1] (64 bit)
	mov 	rax, 7347990519673328018
	shl 	rax, 1
	inc 	rax ;14695981039346656037 == 64 bit fnv1(a) offset basis  

	mov 	rbx, 549755814105
	shl 	rbx, 1
	inc 	rbx ;1099511628211 == 64 bit fnv1(a) prime

.fnv1a_head:
	movzx  	rdx, byte [rsi]
	test 	dl, dl
	jz 	.fnv1a_done
	xor 	rax, rdx
	mul 	rbx
	inc 	rsi
	jmp 	short .fnv1a_head
.fnv1a_done:

;; load data 
	call    .after_data
.begin_encdata:
	incbin  'encoded_solution'
encdata_size equ $-.begin_encdata
	align 	8
.after_data:
	mov 	rsi, [rsp]
	;mov 	rdi, rsi
	;add 	rdi, encdata_size
	lea 	rdi, [rsi+encdata_size]
	;; rax: 64-bit fnv-1a hash of argv[1]
	;; rbx: fnv1(a) prime
	;; rsi: address to encrypted data
	;; rdi: address to end of encrypted data
	;; TOS: address to encrypted data
.decode_loop:
	xor 	[rsi], rax
	mul 	rbx
	add 	rsi, 8
	cmp 	rsi, rdi
	jge 	.data_decoded
	jmp 	short .decode_loop

.data_decoded:

	mov 	eax, SYS_write
	mov 	rdi, STDOUT_FILENO
	pop 	rsi 
	mov 	rdx, encdata_size
	int 	0x80

	

	


	

	xor 	rdi, rdi
;	call 	exit

;; exit --
;; arguments:
;;   rdi: exit code
exit:
	mov	rax, SYS_exit
	int 	0x80

	align 16

end_seg0:
