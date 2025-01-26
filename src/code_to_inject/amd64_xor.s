bits 64

; ===============================
; Push/Pop Multiple Registers Macros
; ===============================
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

; ===============================
; Main Loader Entry
; ===============================
loader_entry_point:
    ; Preserve CPU state
    pushfq                                      ; Save FLAGS register
    pushx rax, rdi, rsi, rdx, rcx, r8, r9       ; Save general-purpose registers

    ; ===============================
    ; Display Loading Message
    ; ===============================
    mov rax, 1                                  ; sys_write syscall
    mov rdi, 1                                  ; file descriptor (stdout)
    lea rsi, [rel msg]                          ; message buffer
    mov rdx, msg_len                            ; message length
    syscall

    ; ===============================
    ; Calculate PIE Offset
    ; ===============================
    lea r12, [rel loader_entry_point]          ; Get current location
    sub r12, [rel info_offset]                 ; Calculate PIE offset

    ; ===============================
    ; Decryption Logic
    ; ===============================
    mov rax, [rel info_addr]                   ; Load address to decrypt
    add rax, r12                               ; Add PIE offset to address
    mov rcx, [rel info_size]                   ; Load size to decrypt
    lea rcx, [rax + rcx]                       ; Calculate end address
    mov rdx, [rel info_key]                    ; Load decryption key

.decrypt_loop:
    xor byte [rax], dl                         ; Decrypt byte
    ror rdx, 8                                 ; Rotate key
    inc rax                                    ; Move to next byte
    cmp rax, rcx                               ; Check if we're done
    jne .decrypt_loop

    ; ===============================
    ; Restore State and Jump
    ; ===============================
    popx r9, r8, rcx, rdx, rsi, rdi, rax       ; Restore registers
    popfq                                      ; Restore FLAGS

    jmp 0xFFFFFFFF                             ; To be patched

; ===============================
; Data Section
; ===============================
msg db "....WOODY....", 10, 0
msg_len equ $ - msg

; ===============================
; Patchable Information Block
; ===============================
info_key:    dq 0xaaaaaaaaaaaaaaaa            ; 64-bit decryption key
info_addr:   dq 0xbbbbbbbbbbbbbbbb            ; 64-bit address to decrypt
info_size:   dq 0xcccccccccccccccc            ; 64-bit size to decrypt
info_offset: dq 0xdddddddddddddddd            ; 64-bit PIE offset