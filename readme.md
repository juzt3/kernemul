# Kernemul

Windows kernel driver and usermode app emulator for x86-64 and ARM64 targets. This can run on multiple host operating systems, such as Windows or Linux. AI was used for assisting development in this project, including the kernel handler implementations.

## How does it work?

The functions of multiple kernel drivers are reimplemented. When the guest (emulated code) executes them, execution is redirected to the host handlers where the call is processed. For drivers, this happens directly. For usermode apps, the syscall ID is mapped to the handler and gets handled in the same way.

## Emulator backends

There are 2 emulator backends: WHP (Windows hypervisor platform) and Unicorn. WHP uses virtualisation to execute instructions a lot faster but is only usable on Windows hosts. Unicorn is regular emulation but will work on different host operating systems too (e.g. Linux). The Unicorn implementation has host multithreading (emulates multiple vCPUs).

# Building

# Usage

# License

This project uses the Apache-2.0 license.
