
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
    mov     r5, output
    add     r6, r2, 1           # Create a valid PDE entry which contains the address of pte1. +1 is to validate entry.
    add     r7, r3, 1
    add     r8, r4, 1
    add     r9, r5, 1
    mov     [0x2204], r1        # Register the address of PDE to the system memory
    mov     [r1 +    0], r6     # Set pte1 to the first entry of PDE  
    mov     [r1 +  288], r7     # Set pte2 to 72nd entry of PDE, 72 = 288 / 4.
    mov     [r2 +   8], 0x2001  # Create an entry of pte1. Map [0x2000, 0x3000) to [0x2000, 0x3000) for write operation.
    mov     [r2 +   32], 0x8001 # Create an entry of pte1. Map [0x8000, 0x9000) to [0x8000, 0x9000) to virtualize pc.
    mov     [r3 + 3348], r8     # Set the address of data to 837th entry of pte2. Map 0x12345000 to data
    mov     [r3 + 3204], r9     # Map 0x12321000 to output
    mov     [0x2200], 1         # Enable virtual memory
    mov     r9, 0x12321000      # store the virtual address of output
    jr      r9
    halt

.align 4096
output:
    mov     r1, 0x12345000      
    mov     r2, [r1]            # Read from 0x12345000, 0b0001001000(72) pde, 0b1101000101(837) pte
    mov     r3, [r1 + 4]
    write   r2                  # Output "A\n"
    write   r3
    halt
