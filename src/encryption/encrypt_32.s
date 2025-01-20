section .text
    global encrypt_32

bits 32

encrypt_32:
    ; Inputs:
    ; rdi: data pointer (char *)
    ; rsi: size of data (size_t)
    ; rdx: key (uint64_t)

    push ebp
    mov ebp, esp

    mov eax, edi    ; rax = data pointer
    mov ecx, esi    ; rcx = size of data

.loop:
    xor byte [eax], dl
    ror edx, 4
    inc eax
    dec ecx
    jnz .loop

    ; restore stack and return
    mov esp, ebp
    pop ebp

    xor eax, eax
    ret

section .note.GNU-stack noalloc noexec nowrite progbits