.text
.p2align 2
.macro begin name
.global \name
.type \name, %function
\name:
.endm
.macro end name
.size \name, .-\name
.endm
begin copy_roundtrip
 stp x19, x30, [sp, #-16]!
 mov x19, x0
 mov x0, #16
 bl imported_malloc
 mov x1, x19
 mov x2, #8
 bl imported_memcpy
 mov x1, #32
 bl imported_realloc
 ldr x19, [x0]
 bl imported_free
 mov x0, x19
 ldp x19, x30, [sp], #16
 ret
end copy_roundtrip
begin fill_buffer
 mov x1, #0x5a
 mov x2, #4
 b imported_memset
end fill_buffer
begin calloc_zero
 stp x19, x30, [sp, #-16]!
 mov x0, #4
 mov x1, #8
 bl imported_calloc
 ldr x19, [x0]
 bl imported_free
 mov x0, x19
 ldp x19, x30, [sp], #16
 ret
end calloc_zero
begin string_length
 b imported_strlen
end string_length
begin compare_strings
 adr x1, expected_string
 b imported_strcmp
end compare_strings
begin limited_compare
 mov x2, #2
 adr x1, expected_string
 b imported_strncmp
end limited_compare
begin checked_copy_bad
 mov x1, x0
 mov x2, #8
 mov x3, #2
 b imported_memcpy_checked
end checked_copy_bad
begin abort_path
 b imported_abort
end abort_path
begin canary_value
 mrs x1, tpidr_el0
 ldr x0, [x1, #40]
 ret
end canary_value
begin custom_call
 b imported_custom
end custom_call
begin printf_call
 b imported_printf
end printf_call
begin snprintf_call
 b imported_snprintf
end snprintf_call
begin copy_to_readonly
 mov x1, x0
 adr x0, expected_string
 mov x2, #4
 b imported_memcpy
end copy_to_readonly
.macro stub name
begin \name
 ret
end \name
.endm
stub imported_malloc
stub imported_memcpy
stub imported_memset
stub imported_calloc
stub imported_realloc
stub imported_free
stub imported_strlen
stub imported_strcmp
stub imported_strncmp
stub imported_memcpy_checked
stub imported_abort
stub imported_custom
stub imported_printf
stub imported_snprintf
.section .rodata
expected_string: .asciz "abd"
