bits 32

; Macros for multiple push/pop operations
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

loader_entry_point32:
    ; ===============================
    ; Register State Preservation
    ; ===============================
    pushx eax, edi, esi, esp, edx, ecx, ebx

    ; ===============================
    ; Display Loading Message
    ; ===============================
    call get_current_address
    sub edx, after_call - loading_message    ; Calculate message address
    mov ecx, edx                             ; Buffer address
    mov edx, loading_message_len             ; Message length
    mov ebx, 1                               ; File descriptor (stdout)
    mov eax, 4                               ; sys_write syscall
    int 0x80

    ; ===============================
    ; PIE (Position Independent Exec) Offset Calculation
    ; ===============================
    call get_current_address
    sub edx, after_call - loader_entry_point32   ; Get current code location
    mov ebx, edx                                 ; Store in ebx
    call get_current_address
    sub edx, after_call - info_offset           ; Get offset info location
    sub ebx, [edx]                              ; Calculate PIE offset

    jmp decrypt_section

; ===============================
; Helper Functions
; ===============================
get_current_address:
    call after_call
after_call:
    pop edx
    ret

; ===============================
; Decryption Logic
; ===============================
decrypt_section:
    ; Load decryption parameters
    call get_current_address
    sub edx, after_call - info_addr
    mov eax, [edx]                          ; Load address to decrypt
    call get_current_address
    sub edx, after_call - info_size
    mov ecx, [edx]                          ; Load size to decrypt
    call get_current_address
    sub edx, after_call - info_key
    mov edx, [edx]                          ; Load decryption key
    
    ; Apply PIE offset to address
    add eax, ebx
    add ecx, eax                            ; Calculate end address

.decrypt_loop:
    xor byte [eax], dl                      ; Decrypt byte
    ror edx, 8                              ; Rotate key
    inc eax                                 ; Move to next byte
    cmp eax, ecx                            ; Check if we're done
    jnz .decrypt_loop

    ; ===============================
    ; Cleanup and Jump to Entry
    ; ===============================
    popx eax, edi, esi, esp, edx, ecx, ebx
    jmp 0xFFFFFFFF                          ; To be patched

; ===============================
; Data Section
; ===============================
loading_message db "....WOODY....", 10, 0
loading_message_len equ $ - loading_message


; ===============================
; Patchable Information Block
; ===============================
info_key:    dd 0xaaaaaaaa                  ; Decryption key
info_addr:   dd 0xbbbbbbbb                  ; Address to decrypt
info_size:   dd 0xcccccccc                  ; Size to decrypt
info_offset: dd 0xdddddddd                  ; PIE offset