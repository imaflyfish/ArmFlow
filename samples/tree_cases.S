// SPDX-License-Identifier: GPL-2.0-only
.text
.p2align 2
// style: 0 compact, 1 padding, 2 fallthrough, 3 live slot, 4 escaped stack,
// 5 live reload register, 6 changed selection flags, 7 live handler flags.
.macro tree name, style
.global \name
.type \name,%function
\name:
 sub sp,sp,#16
 mov w8,#0
 str w8,[sp]
 b .Lhead\@
.Lhead\@:
 ldr w8,[sp]
 cmp w8,#0
 b.eq .Lchoose\@
 cmp w8,#1
 b.eq .Lleft\@
 cmp w8,#2
 b.eq .Lright\@
 brk #1
.Lchoose\@:
 .if \style == 4
 mov x12,sp
 .endif
 .if \style == 8
 mov w19,#1
 .else
 mov w9,#1
 .endif
 mov w10,#2
 cmp w0,#0
 .if \style == 8
 csel w19,w19,w10,eq
 .else
 csel w9,w9,w10,eq
 .endif
 .if \style == 6
 cmp w0,#7
 .endif
 .if \style == 8
 str w19,[sp]
 .else
 str w9,[sp]
 .endif
 .if \style == 1
 nop
 .endif
 b .Lhead\@
 .if \style != 2
 brk #2
 .endif
.Lleft\@:
 .if \style == 3
 ldr w0,[sp]
 .elseif \style == 5
 mov w0,w8
 .elseif \style == 7
 cset w0,eq
 .else
 mov x0,#11
 .endif
 mov w8,#0
 mov w9,#0
 add sp,sp,#16
 ret
.Lright\@:
 .if \style == 3
 ldr w0,[sp]
 .elseif \style == 5
 mov w0,w8
 .elseif \style == 7
 cset w0,eq
 .else
 mov x0,#23
 .endif
 mov w8,#0
 mov w9,#0
 add sp,sp,#16
 ret
.size \name,.-\name
.endm
tree tree_compact,0
tree tree_padding,1
tree tree_fallthrough,2
tree tree_live_slot,3
tree tree_escaped_slot,4
tree tree_live_register,5
tree tree_changed_flags,6
tree tree_live_flags,7
tree tree_callee_saved,8
.global tree_callee_observer
.type tree_callee_observer,%function
tree_callee_observer:
 stp x19,x30,[sp,#-16]!
 mov x19,#99
 bl tree_callee_saved
 mov x0,x19
 ldp x19,x30,[sp],#16
 ret
.size tree_callee_observer,.-tree_callee_observer
.section .rodata
.byte 0
.text
.p2align 2
.global tree_bst_bounds
.type tree_bst_bounds,%function
tree_bst_bounds:
 sub sp,sp,#16
 mov w8,#1
 str w8,[sp]
 b .Lbounds_head
.Lbounds_head:
 ldr w8,[sp]
 cmp w8,#2
 b.lo .Lbounds_low
 cmp w8,#2
 b.eq .Lbounds_done
 brk #3
.Lbounds_low:
 cmp w8,#3
 b.eq .Lbounds_impossible
 cmp w8,#1
 b.eq .Lbounds_initial
 brk #4
.Lbounds_initial:
 add x0,x0,#5
 mov w8,#2
 str w8,[sp]
 b .Lbounds_head
.Lbounds_done:
 add sp,sp,#16
 ret
.Lbounds_impossible:
 mov x0,#999
 add sp,sp,#16
 ret
.size tree_bst_bounds,.-tree_bst_bounds
