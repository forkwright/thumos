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
    __stack_top = . + 0x10000;                  /* SVC boot stack (64 KB) */
    __irq_stack_top = __stack_top + 0x1000;     /* IRQ banked stack (4 KB) */
    __abt_stack_top = __irq_stack_top + 0x1000; /* ABT banked stack (4 KB) */
    __und_stack_top = __abt_stack_top + 0x1000; /* UND banked stack (4 KB) */

    /DISCARD/ : {
        *(.comment)
        *(.ARM.attributes)
        *(.ARM.exidx*)
    }
}

/* Kernel image + all stacks must stay inside the reserved window ending at
   kconfig::KERNEL_END (0x40100000): page::init hands out frames from there
   up, so an oversized image would be silently overwritten by allocations. */
ASSERT(__und_stack_top <= 0x40100000, "kernel image + stacks exceed KERNEL_RESERVED; grow kconfig::KERNEL_RESERVED/KERNEL_END and the memguard map together")
