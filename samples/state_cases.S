// SPDX-License-Identifier: GPL-2.0-only
.text
.p2align 2
.global state_chain
.type state_chain,%function
state_chain:
 sub sp,sp,#16
 mov w8,#0
 str w8,[sp]
 adr x9,chain_indices
 adr x10,chain_targets
 b .Lchain_head
.Lchain_head:
 ldrsw x8,[sp]
 ldrsw x11,[x9,x8,lsl #2]
 ldr x12,[x10,x11,lsl #3]
 br x12
.Lchain_first:
 add x0,x0,#7
 ldr w8,[sp]
 eor w8,w8,#1
 add w8,w8,#3
 sub w8,w8,#1
 orr w8,w8,#4
 and w8,w8,#3
 str w8,[sp]
 b .Lchain_head
.Lchain_second:
 add x0,x0,#11
 ldr w8,[sp]
 sub w8,w8,#2
 str w8,[sp]
 b .Lchain_head
.Lchain_done:
 add x0,x0,#19
 add sp,sp,#16
 ret
.size state_chain,.-state_chain
.global state_cycle
.type state_cycle,%function
state_cycle:
 sub sp,sp,#16
 mov w8,#0
 str w8,[sp]
 adr x9,cycle_indices
 adr x10,cycle_targets
 b .Lcycle_head
.Lcycle_head:
 ldrsw x8,[sp]
 ldrsw x11,[x9,x8,lsl #2]
 ldr x12,[x10,x11,lsl #3]
 br x12
.Lcycle_body:
 ldr w8,[sp]
 eor w8,w8,#1
 str w8,[sp]
 b .Lcycle_head
.size state_cycle,.-state_cycle
.global state_wrap
.type state_wrap,%function
state_wrap:
 sub sp,sp,#16
 mov w8,#0
 str w8,[sp]
 adr x9,wrap_zero
 adr x10,wrap_targets
 b .Lwrap_head
.Lwrap_head:
 ldrsw x8,[sp]
 ldrsw x11,[x9,x8,lsl #2]
 ldr x12,[x10,x11,lsl #3]
 br x12
.Lwrap_body:
 ldr w8,[sp]
 sub w8,w8,#1
 str w8,[sp]
 b .Lwrap_head
.Lwrap_done:
 add sp,sp,#16
 ret
.size state_wrap,.-state_wrap
.section .rodata
.p2align 3
chain_indices: .word 0,1,2,3
chain_targets: .quad .Lchain_first,.Lchain_done,0,.Lchain_second
cycle_indices: .word 0,1
cycle_targets: .quad .Lcycle_body,.Lcycle_body,0
.word 1
wrap_zero: .word 0
.p2align 3
wrap_targets: .quad .Lwrap_body,.Lwrap_done,0
