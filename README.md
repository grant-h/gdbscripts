# GDB Scripts
An assorted collection of my personal GDB scripts, divided by architecture.

To use, clone the repository and `source` the specific scripts you want from GDB or your .gdbinit.
These scripts are provided AS IS and are not guaranteed to work on your system.

That said, if you find a bug, open a PR or issue.
Scripts tested on Ubuntu 16.04 with GDB 7.11.1.
For development, edit the script, save, and then re-`source` it.

## Index
- AArch64
  * [aarch64-pagewalk.py](/aarch64/aarch64-pagewalk.py) - Decodes and prints out page table entries for EL1 (TTBR0 and TTBR1), EL2, or EL3. Supports multiple page table configurations.
