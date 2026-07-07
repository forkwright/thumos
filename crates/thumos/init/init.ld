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

    /* WHY (#482) ALIGN(4096) at each permission-class boundary: spawn_user maps
       the image per-segment with W^X user page permissions (.text RX,
       .rodata RO+XN, .data/.bss RW+XN). A 4 KB page must therefore fall
       entirely in ONE permission class -- page-aligning the section starts
       guarantees no page carries both executable and writable content.
       max-page-size=0x100 (build.rs) keeps the FILE offsets compact regardless,
       so the image stays small; #475's contiguous alloc covers it either way. */
    .text : {
        *(.text.boot)
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata : {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);
    .data : {
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
