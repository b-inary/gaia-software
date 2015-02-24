.global timer_count
timer_count:
  .int 0

.global trap
trap:
  enter 0
  br L1
L_case_trap_0_1:
  mov r2, timer_count
  mov r1, [r2]
  add r3, r1, 1
  mov [r2], r3
  mov r1, timer_count
  mov r1, [r1]
  cmpgt r1, r1, 50
  cmpeq r1, r1, 0
  bz r1, L3
  mov r3, 2147491840
  mov r1, 84
  mov [r3], r1
L3:
  mov r1, timer_count
  mov r1, [r1]
  cmpgt r1, r1, 100
  bz r1, L5
sysenter
  mov r3, timer_count
  mov r1, 0
  mov [r3], r1
L5:
  br L2
L_case_trap_0_2:
  mov r3, 2147491840
  mov r1, 75
  mov [r3], r1
  mov r3, 2147491840
  mov r1, 2147491840
  mov r1, [r1]
  mov [r3], r1
  br L2
L_case_trap_0_3:
  mov r3, 2147491840
  mov r1, 83
  mov [r3], r1
  br L2
L_default_trap_0:
  mov r3, 2147491840
  mov r1, 69
  mov [r3], r1
  br L2
L1:
  mov r1, 2147492108
  mov r1, [r1]
  mov r3, 1
  beq r1, r3, L_case_trap_0_1
  mov r3, 2
  beq r1, r3, L_case_trap_0_2
  mov r3, 3
  beq r1, r3, L_case_trap_0_3
  br L_default_trap_0
L2:
  mov r1, 2147492104
  mov r3, 2147492104
  mov r3, [r3]
  sub r3, r3, 4
  mov [r1], r3
sysexit
  mov r1, 0
  leave
  ret

.global main
main:
  enter 0
  mov r2, 2147492096
  mov r1, trap
  mov [r2], r1
  mov r2, 2147492100
  mov r1, 1
  mov [r2], r1
L7:
  mov r1, 2
  br L7
  mov r1, 0
  leave
  halt

