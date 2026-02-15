section .text
    global encrypt_64

encrypt_64:
    ; XOR stream cipher used for both encryption and decryption.
    ;
    ; Calling convention (System V AMD64):
    ;   rdi: data pointer (char *)
    ;   rsi: size of data (size_t)
    ;   rdx: key (uint64_t)
    ;
    ; Algorithm:
    ;   for i in [0..size):
    ;     data[i] ^= (key & 0xff)
    ;     key = ror(key, 8)
    ; Inputs:
    ; rdi: data pointer (char *)
    ; rsi: size of data (size_t)
    ; rdx: key (uint64_t)

    push rbp
    mov rbp, rsp

    mov rax, rdi    ; rax = data pointer
    mov rcx, rsi    ; rcx = size of data

.loop:
    xor byte [rax], dl
    ror rdx, 8
    inc rax
    dec rcx
    jnz .loop

    ; restore stack and return
    mov rsp, rbp
    pop rbp

    xor rax, rax
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
