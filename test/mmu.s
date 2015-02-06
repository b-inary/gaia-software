
.align 4096
pde:
    .int    0, 1024
pte1:
    .int    0, 1024
pte2:
    .int    0, 1024
data:
    .int    65
    .int    10

.align 4096
.global main
main:
    mov     r1, pde
    mov     r2, pte1
    mov     r3, pte2
    mov     r4, data
    add     r5, r2, 1
    add     r6, r3, 1
    add     r7, r4, 1
    mov     [0x2204], r1
    mov     [r1 +    0], r5
    mov     [r1 +  288], r6
    mov     [r2 +    8], 0x2001
    mov     [r3 + 3348], r7
    mov     [0x2200], 1
    mov     r1, 0x12345000
    mov     r2, [r1]
    mov     r3, [r1 + 4]
    write   r2
    write   r3
    halt
