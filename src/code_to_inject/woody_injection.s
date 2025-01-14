bits 64
ORG 0x0

_start:
    ; Debug detection chain
    ; call detect_debugger
    ; test rax, rax
    ; jnz scramble_and_exit

    ; Obfuscated control flow to reach decryption
    xor rax, rax  ; Clear rax
    inc rax       ; Set rax to 1
    test rax, rax ; Always true, used for control flow obfuscation
    jz no_decrypt ; Jump never taken, but confuses analysis

    ; Decrypt
    jmp decrypt   ; Jump to actual decryption

detect_debugger:
    ; Ptrace detection
    xor rax, rax
    mov rdi, 0x1         ; PTRACE_TRACEME
    syscall              ; syscall: ptrace(PTRACE_TRACEME, 0, 0, 0)
    test rax, rax
    sete al              ; If ptrace fails, AL = 1
    ret                  ; Return 1 if debugger detected, 0 otherwise

scramble_and_exit:
    ; Scramble key and exit
    lea rdi, [rel key]
    xor rsi, rsi
    mov rcx, 32          ; Key length
    .scramble_loop:
        mov byte [rdi + rsi], 0xFF
        inc rsi
        loop .scramble_loop

    ; Exit program
    mov rax, 60          ; syscall: exit
    xor rdi, rdi
    syscall

no_decrypt:
    ; Dead code - this block is never executed
    mov rbx, 0x12345678
    add rbx, 0x1234
    ret

decrypt:
    ; Load necessary information for decryption
    mov r8, [key]               ; Key in r8
    mov r9, [old_entry]         ; Original entry in r9
    mov r10, [encrypted_start]  ; Start address of encrypted section
    mov r11, [encrypted_size]   ; Size of encrypted section
    xor rdi, rdi                ; Clear key index

decrypt_loop:
    ; XOR decryption loop with obfuscation
    xor r12d, r12d           ; Clear r12 for byte operations
    mov r12b, [r10]          ; Load byte from encrypted section
    mov r13b, [r8 + rdi]     ; Load key byte using index (rdi)
    xor r12b, r13b           ; XOR with key byte
    mov [r10], r12b          ; Store decrypted byte back

    ; Obfuscation block (junk instructions)
    mov r14d, 0x1            ; Redundant instruction
    xor r14d, r14d           ; Redundant clearing
    or r14d, 0x55555555      ; Dummy computation
    shr r14d, 4              ; Shift operation (junk)

    ; Obfuscated key rotation
    inc rdi                  ; Next key byte index
    cmp rdi, 32              ; Key length (32 bytes)
    jb key_index_ok          ; If within bounds, continue
    xor rdi, rdi             ; Reset index to 0
    mov r15, r8              ; Redundant move for obfuscation
    rol r15, 1               ; Rotate key left
    mov r8, r15              ; Store rotated key back

key_index_ok:
    ; Another obfuscation block
    xor r14, r14             ; Clear a random register
    test r14, r14            ; Always false, just for confusion
    jne fake_jump            ; Never taken

    dec r11                  ; Decrease counter
    jnz decrypt_loop         ; Continue if not zero

    ; When done looping jump to printing block
    jmp decrypt_done         ; Jump to decrypt_done after decryption is complete


fake_jump:
    ; Dead code (never executed)
    mov rbx, 0xDEADBEEF
    add rbx, 0xBAAD
    ret

decrypt_done:
    ; Print message after decryption
    mov rax, 1               ; sys_write
    mov rdi, 1               ; File descriptor 1 is stdout
    mov rsi, msg             ; Address of message
    mov rdx, [msg_len]       ; Length of message - adjusted for variable size
    syscall

    ; Opaque predicate to confuse analysis
    mov rcx, 1
    cmp rcx, 1
    jne skip_jmp             ; This jump is never taken
    jmp r9                   ; Jump to original entry point

skip_jmp:
    ; Dead code block
    mov rbx, 0x90909090
    ret

; Padding or anti-disassembly trick
db 0x90, 0x90, 0x90, 0x90

; Message placeholder
msg times 14 db 0x42         ; Marker: 'B'
msg_len dq 0x4343434343434343 ; Marker: 'CCCCCCCC'

; Metadata for decryption
key times 32 db 0x44           ; Marker: 'D' (key size 32 bytes)
encrypted_start dq 0x4545454545454545 ; Marker: 'EEEEEEEE'
encrypted_size dq 0x4646464646464646  ; Marker: 'FFFFFFF'

; Original entry point
old_entry dq 0x4747474747474747 ; Marker: 'GGGGGGGG'
