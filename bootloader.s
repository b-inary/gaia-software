
# asm.py -e 0 -r

# set constants
.set    ENTRY_POINT, 0x3000
.set    MEMORY_SIZE, 0x400000

    # init rsp and rbp
    mov     rsp, MEMORY_SIZE
    mov     rbp, MEMORY_SIZE

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

    # jump to entry point
    jr      r3
