section .text
    global encrypt

encrypt:
    ; Input:
    ; rdi: data pointer
    ; rsi: size of data
    ; rdx: key pointer

    xor r8, r8              ; Clear r8 (key index)
    xor r9, r9              ; Clear r9 (processed size)

encrypt_loop:
    cmp r9, rsi             ; Have we processed all data?
    jge encrypt_done        ; If yes, jump to done

    ; Load data byte
    mov al, [rdi + r9]      ; Load data byte into al
    ; Load key byte
    mov bl, [rdx + r8]      ; Load key byte into bl
    ; XOR data with key
    xor al, bl              ; XOR al with bl
    ; Store result back
    mov [rdi + r9], al      ; Store result back in data

    ; Increment indices
    inc r8                  ; Increment key index
    cmp r8, 32              ; Key size is 32 bytes
    jb key_index_ok         ; If within bounds, continue
    xor r8, r8              ; Reset key index to 0

key_index_ok:
    inc r9                  ; Increment processed size
    jmp encrypt_loop        ; Repeat loop

encrypt_done:
    xor rax, rax            ; Clear rax
    ret

section .note.GNU-stack noalloc noexec nowrite progbits