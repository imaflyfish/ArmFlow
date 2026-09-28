// SPDX-License-Identifier: GPL-2.0-only
// Neutral AArch64 fixtures written for ArmFlow; no third-party target code.
.text
.p2align 2
.global two_constant
.type two_constant,%function
two_constant:
 sub sp,sp,#16
 mov w8,#0
 str w8,[sp]
 adr x9,indices
 adr x10,two_constant_targets
 ldrsw x8,[sp]
 ldrsw x11,[x9,x8,lsl #2]
 ldr x12,[x10,x11,lsl #3]
 br x12
.Lconstant_handler:
 add x0,x0,#7
 add sp,sp,#16
 ret
.size two_constant,.-two_constant

.global two_choice
.type two_choice,%function
two_choice:
 sub sp,sp,#16
 mov w8,#0
 mov w9,#1
 cmp w0,#0
 csel w8,w8,w9,eq
 str w8,[sp]
 adr x9,indices
 adr x10,two_choice_targets
 ldrsw x8,[sp]
 ldrsw x11,[x9,x8,lsl #2]
 ldr x12,[x10,x11,lsl #3]
 br x12
.Lchoice_zero:
 mov x12,#0
 add x0,x0,#7
 add sp,sp,#16
 ret
.Lchoice_other:
 mov x12,#0
 sub x0,x0,#3
 add sp,sp,#16
 ret
.size two_choice,.-two_choice

.global single_choice
.type single_choice,%function
single_choice:
 mov w8,#0
 mov w9,#1
 cmp w0,#0
 csel w8,w8,w9,eq
 adr x10,single_targets
 ldr x12,[x10,w8,uxtw #3]
 br x12
.Lsingle_zero:
 mov x12,#0
 add x0,x0,#11
 ret
.Lsingle_other:
 mov x12,#0
 add x0,x0,#19
 ret
.size single_choice,.-single_choice

.global shared_dispatch
.type shared_dispatch,%function
shared_dispatch:
 sub sp,sp,#16
 adr x9,indices
 adr x10,shared_targets
 cbnz w0,.Lshared_nonzero
 mov w8,#0
 str w8,[sp]
 b .Lshared_head
.Lshared_nonzero:
 mov w8,#1
 str w8,[sp]
 b .Lshared_head
.Lshared_head:
 ldrsw x8,[sp]
 ldrsw x11,[x9,x8,lsl #2]
 ldr x12,[x10,x11,lsl #3]
 br x12
.Lshared_zero:
 add x0,x0,#23
 add sp,sp,#16
 ret
.Lshared_one:
 add x0,x0,#31
 add sp,sp,#16
 ret
.size shared_dispatch,.-shared_dispatch

.global compare_tree
.type compare_tree,%function
compare_tree:
 sub sp,sp,#16
 mov w8,#0
 str w8,[sp]
 b .Ltree_head
.Ltree_head:
 ldr w8,[sp]
 cmp w8,#0
 b.eq .Ltree_initial
 cmp w8,#1
 b.eq .Ltree_done
 brk #1
.Ltree_initial:
 add x0,x0,#2
 mov w8,#1
 str w8,[sp]
 b .Ltree_head
.Ltree_done:
 add sp,sp,#16
 ret
.size compare_tree,.-compare_tree

.global flag_changed
.type flag_changed,%function
flag_changed:
 mov w8,#0
 mov w9,#1
 cmp w0,#0
 csel w8,w8,w9,eq
 cmp w0,#7
 adr x10,single_targets
 ldr x12,[x10,w8,uxtw #3]
 br x12
.size flag_changed,.-flag_changed

.global bit_selected
.type bit_selected,%function
bit_selected:
 ldarb w8,[x0]
 sbfx w8,w8,#0,#1
 and w8,w8,#1
 adr x10,bit_targets
 ldr x12,[x10,w8,uxtw #3]
 br x12
.Lbit_zero:
 mov x12,#0
 mov x0,#41
 ret
.Lbit_one:
 mov x12,#0
 mov x0,#43
 ret
.size bit_selected,.-bit_selected

.section .rodata
.p2align 3
indices: .word 0,1
.p2align 3
two_constant_targets: .quad .Lconstant_handler,0
two_choice_targets: .quad .Lchoice_zero,.Lchoice_other,0
single_targets: .quad .Lsingle_zero,.Lsingle_other,0
shared_targets: .quad .Lshared_zero,.Lshared_one,0
bit_targets: .quad .Lbit_zero,.Lbit_one,0
