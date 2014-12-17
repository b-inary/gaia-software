
.global read_int
read_int:
    read    r4
    read    r3
    read    r2
    read    r1
    shl     r2, r2,  8
    shl     r3, r3, 16
    shl     r4, r4, 24
    add     r1, r1, r2
    add     r3, r3, r4
    add     r1, r1, r3
    ret

.global print_int
print_int:
    shr     r2, r1,  8
    shr     r3, r1, 16
    shr     r4, r1, 24
    write   r4
    write   r3
    write   r2
    write   r1
    ret

