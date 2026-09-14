# Kernemul

Windows kernel driver and usermode app emulator for x86-64 and ARM64 targets. AI was used for assisting development in this project, including the kernel handler implementations.

## How does it work?

The functions of multiple kernel drivers are reimplemented. When the guest (emulated code) executes them, execution is redirected to the host handlers where the call is processed. For drivers, this happens directly. For usermode apps, the syscall ID is mapped to the handler and gets handled in the same way.