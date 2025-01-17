bits 64

%macro pushx 1-*
 %rep %0
   push %1
   %rotate 1
 %endrep
%endmacro

%macro popx 1-*
  %rep %0
    %rotate -1
    pop %1
  %endrep
%endmacro

section .text

loader_entry_point:
	pushfq
	pushx rax, rdi, rsi, rsp, rdx, rcx

    ; syscall : rax
    ; parameter order : rdi, rsi, rdx, r10, r8, r9
    ; sys_write
  	mov rax, 1
	mov	rdi, rax
	lea	rsi, [rel msg]
	mov	rdx, msg_len
	syscall

    ; We save pie offset
	lea r12, [rel loader_entry_point] ; r12 = loader_entry_point. The e_entry of the binary
	sub r12, [rel info_offset]		; So if the entry is 0x0000000000000700 and the info offset is 0x0000000000000700, r12 = 0x0000000000000000

	; We jump to the unpacking code
	jmp	start_unpacking

msg	db	"....Woody....", 10, 0
msg_len	equ	$ - msg

start_unpacking:
	mov	rax, [rel info_addr] 	; rax = info_addr, the beggining of the .text section
	mov	rcx, [rel info_size]	; rcx = info_size, the size of the .text section
	mov	rdx, [rel info_key]		; rdx = info_key, the key to decrypt the .text section

    ; We add PIE offset
	add rax, r12	; rax = rax + r12 in our case since r12 = 0x0000000000000000, rax = rax
	add	rcx, rax 	; rcx = rcx + rax in our case since rax = rax, rcx = rcx. When rcx reaches the end of the .text section, we stop the loop

.loop:
	xor	byte [rax], dl	; xor the byte at rax with the key. dl is the lower 8 bits of rdx
	ror	rdx, 8			; rotate the key by 8 bits
	inc	rax				; increment rax by 1
	cmp	rax, rcx		; compare rax with rcx (rax is the current byte we are decrypting, rcx is the end of the .text section)
	jnz	.loop			; If rax is not equal to rcx, we loop again (jnz = jump if not zero)

	; We jump to the decrypted code
	popx rax, rdi, rsi, rsp, rdx, rcx
	popfq
	jmp	0xFFFFFFFF

; random values here, to be patched
info_start:
info_key:	    dq	0xaaaaaaaaaaaaaaaa
info_addr:	    dq	0xbbbbbbbbbbbbbbbb
info_size:	    dq  0xcccccccccccccccc
info_offset:    dq  0xdddddddddddddddd
