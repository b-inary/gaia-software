
# asm.py -e 0x80000000 -r

# set constants
.set    ENTRY_POINT, 0x1000
.set    MEMORY_SIZE, 0x400000

    # init rsp and rbp
    mov     rsp, MEMORY_SIZE
    mov     rbp, MEMORY_SIZE

    # display prompt
    write   r1, "\r\n"
    write   r1, "GAIA Architecture\r\n"
    write   r1, "\r\n"
    write   r1, "Waiting for input...\r\n"

    # load file size
    read    r1
    read    r2
    read    r3
    read    r4
    shl     r1, r1, 24
    shl     r2, r2, 16
    shl     r3, r3,  8
    add     r1, r1, r2
    add     r3, r3, r4
    add     r1, r1, r3

    # load program
    mov     r2, 0
    mov     r3, ENTRY_POINT
    beq-    r1, r2, load_end
load_loop:
    and     r9, r2, 1023
    bnz     r9, load_next
    call    display_progress
load_next:
    read    r5
    read    r6
    read    r7
    read    r8
    shl     r5, r5, 24
    shl     r6, r6, 16
    shl     r7, r7,  8
    add     r5, r5, r6
    add     r7, r7, r8
    add     r5, r5, r7
    add     r4, r2, r3
    mov     [r4], r5
    add     r2, r2, 4
    bne+    r1, r2, load_loop
load_end:
    write   r1, "\rLoading completed!              \r\n"
    write   r1, "\r\n"

    # jump to entry point
    jr      r3


display_progress:
    enter
    write   r11, "\rLoading... ["
    shr     r11, r2, 10
    call    display_decimal
    write   r11, " KB / "
    add     r11, r1, 1023
    shr     r11, r11, 10
    call    display_decimal
    write   r11, " KB]"
    leave
    ret

display_decimal:
    enter
    blt     r11, 10, dec_lt10
    blt     r11, 100, dec_lt100
    blt     r11, 1000, dec_lt1000
    mov     r12, 1000
    call    display_digit
    mov     r12, 44     # ',' character
    write   r12
dec_lt1000:
    mov     r12, 100
    call    display_digit
dec_lt100:
    mov     r12, 10
    call    display_digit
dec_lt10:
    mov     r12, 1
    call    display_digit
    leave
    ret

display_digit:
    mov     r13, 48
    br      dig_cond
dig_loop:
    sub     r11, r11, r12
    add     r13, r13, 1
dig_cond:
    bge     r11, r12, dig_loop
    write   r13
    ret
