
# -l lib.s

fib:
    enter   2
    blt     r1, 2, fib_ret
    mov     [rbp - 4], r1
    sub     r1, r1, 1
    call    fib
    mov     [rbp - 8], r1
    mov     r1, [rbp - 4]
    sub     r1, r1, 2
    call    fib
    mov     r2, [rbp - 8]
    add     r1, r1, r2
    leave
fib_ret:
    ret

.global main
main:
    call    read_int
    call    fib
    call    print_int
    halt

