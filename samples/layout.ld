ENTRY(two_constant)
PHDRS { instructions PT_LOAD FLAGS(5); tables PT_LOAD FLAGS(4); }
SECTIONS {
 . = 0x100000;
 .text : { *(.text*) } :instructions
 . = 0x180000;
 .rodata : { *(.rodata*) } :tables
 /DISCARD/ : { *(.comment) *(.note*) }
}
