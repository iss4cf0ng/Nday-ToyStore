[BITS 32]

popad
add [byte edx + 0], dh
add eax, 0x11001500
add [byte edx + 0], dh
sub eax, 0x11001100
add [byte edx + 0], dh
push eax
add [byte edx + 0], dh
ret