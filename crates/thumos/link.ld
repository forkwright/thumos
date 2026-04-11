/* Linker script for thumos on MT6739 */
/* Kernel loads at 0x40008000 (same as Linux on this platform) */

ENTRY(_start)

SECTIONS
{
    . = 0x40008000;

    .text : {
        *(.text.boot)
        *(.text .text.*)
    }

    .rodata : ALIGN(4) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4) {
        *(.data .data.*)
    }

    .bss : ALIGN(4) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    . = ALIGN(4096);
    __stack_top = . + 0x10000;

    /DISCARD/ : {
        *(.comment)
        *(.ARM.attributes)
        *(.ARM.exidx*)
    }
}
