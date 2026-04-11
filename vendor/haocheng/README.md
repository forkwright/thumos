# vendor/haocheng

Vendored MT6739 driver reference code from the Haocheng BSP (Board Support Package)
shipped with the AGM M7.

## Purpose

These files are used as **reference documentation only** during kernel development.
They provide register offsets, hardware initialization sequences, and GPIO/feature
bindings for the MT6739 SoC as configured by the Haocheng ODM.

## Build status

**Not compiled.** Nothing in this directory is included in any Cargo build or
linked into the thumos kernel. The files exist solely to be read by developers
while writing Rust drivers that target the same hardware.

## Contents

- `drivers/hct_include/hct_project_all_config.h` -- GPIO and feature configuration
  bindings for the AGM M7 board variant. Currently a stub header (feature bindings
  absent; kernel boots without LCM probing).

## License

The original header file contained no license header or copyright notice. The
vendored stub retains the same absence. Treat as proprietary reference material.
