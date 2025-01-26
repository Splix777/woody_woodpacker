section .text
    global encrypt_32

encrypt_32:
    ; Inputs:
    ; rdi: data pointer (char *)
    ; rsi: size of data (size_t)
    ; rdx: key (uint32_t, but passed as 64-bit)

    push rbp
    mov rbp, rsp

    mov rax, rdi    ; rax = data pointer
    mov rcx, rsi    ; rcx = size of data
    mov edx, edx    ; Use only the lower 32 bits of rdx (key)

.loop:
    xor byte [rax], dl
    ror edx, 8      ; Rotate the 32-bit key
    inc rax
    dec rcx
    jnz .loop

    ; Restore stack and return
    mov rsp, rbp
    pop rbp

    xor rax, rax    ; Return 0 (success)
    ret

section .note.GNU-stack noalloc noexec nowrite progbits