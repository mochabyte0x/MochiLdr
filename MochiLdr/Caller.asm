
; Author: mochabyte
; Inspired from: Paul Ungur (5pider), Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012

option casemap:none

PUBLIC MochiCaller

.code

MochiCaller PROC
    call    get_base
    nop
get_base:
    pop     rcx
    xchg    rsi, rsi
    lea     r8, [rcx]             ; Random Obfuscation
    xor     ebx, ebx
    mov     bx, 5A4Dh             ; "MZ" Header
    nop
    mov     r9, r9
    xor     edx, edx
    mov     dx, 4550h             ; "PE" Header
scan_mz:
    dec     rcx
    nop
    cmp     word ptr [rcx], bx
    jne     scan_mz
    mov     eax, dword ptr [rcx + 3Ch] ; e_lfanew value
    lea     rax, [rcx + rax]
    xchg    r10, r10
    cmp     word ptr [rax], dx
    jne     scan_mz
    mov     rax, rcx
    xchg    r11, r11
    ret
MochiCaller ENDP

END
