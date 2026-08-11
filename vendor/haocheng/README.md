# vendor/haocheng

Vendored MT6739 driver reference code from the Haocheng BSP (Board Support Package)
shipped with the AGM M7.

## Purpose

Kernel developers use these files as **reference documentation only** during
kernel development. They provide register offsets, hardware initialization
sequences, and GPIO/feature bindings for the MT6739 SoC as configured by the
Haocheng ODM.

## Build status

**Not compiled.** No Cargo build includes anything in this directory, and the
thumos kernel links none of it. Developers read the files solely as reference
while writing Rust drivers that target the same hardware.

## Contents

- `drivers/hct_include/hct_project_all_config.h` -- GPIO and feature configuration
  bindings for the AGM M7 board variant. As of this commit, the header is a stub
  (feature bindings absent, so the kernel boots without LCM probing).

## License

The original header file contained no license header or copyright notice. The
vendored stub retains the same absence. Treat as proprietary reference material.
