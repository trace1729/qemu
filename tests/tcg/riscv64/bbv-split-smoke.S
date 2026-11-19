#include <asm/unistd.h>

	.text
	.globl _start
_start:
	.option norvc
	li t0, 10000
	li t1, 0
	li t2, 0
loop:
	addi t0, t0, -1
	addi t1, t1, 1
	addi t2, t2, 3
	bne t0, zero, loop
	li a0, 0
	li a7, __NR_exit
	ecall
