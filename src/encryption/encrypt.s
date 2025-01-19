section .text
    global encrypt

encrypt:
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