/* Linker script for thumos /init (#474). */
/* Base at 0x7FF0_0000 (kconfig::USER_TEXT_BASE): the kernel maps the top 1 MB
   of DRAM as the executable userspace text region and excludes it from the
   page allocator, so a spawned ELF runs here without an XN prefetch abort
   (all other DRAM is execute-never per W^X #417) and without colliding with
   kernel page allocations. The ELF loader is identity-mapping (p_vaddr ==
   physical write address); basing the whole image here keeps the ELF + program
   headers in-range, and /DISCARD/ drops the metadata sections that would
   otherwise emit a separate low segment. */

ENTRY(_start)

SECTIONS
{
    . = 0x7FF00000;

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
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.ARM.exidx*)
        *(.ARM.attributes)
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.eh_frame_hdr*)
    }
}
