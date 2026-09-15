# Kernemul

Windows kernel driver and usermode app emulator for x86-64 and ARM64 targets. This can run on multiple host operating systems, such as Windows or Linux. AI was used for assisting development in this project, including the kernel handler implementations.

## How does it work?

The functions of multiple kernel drivers are reimplemented. When the guest (emulated code) executes them, execution is redirected to the host handlers where the call is processed. For drivers, this happens directly. For usermode apps, the syscall ID is mapped to the handler and gets handled in the same way.

### Example handler syntax

```cpp
state.redirect(mod, "KeSetEvent",
    [](vcpu&, emu_object<_KEVENT> event, const std::int32_t increment,
        const std::uint8_t wait) -> std::int32_t
    {
        if (!event)
            return 0;

        const auto previous = win::signal_state(event);
        win::set_signal_state(event, 1);

        THREAD_LOG_INFO("KeSetEvent(event=0x{:X}, increment={}, wait={}) -> {}",
            event.address(), increment, wait, previous);

        return previous;
    });
```

## Emulator backends

There are 2 emulator backends: WHP (Windows hypervisor platform) and Unicorn. WHP uses virtualisation to execute instructions a lot faster but is only usable on Windows hosts. Unicorn is regular emulation but will work on different host operating systems too (e.g. Linux). The Unicorn implementation has host multithreading (emulates multiple vCPUs).

# Getting started

First clone the repository.

```
git clone --recurse-submodules https://github.com/noahware/kernemul.git
```

Then you need to choose what target you will choose:

x64 targets via WHP/Hyper-V (x64 Windows hosts only):

```
cmake --preset x64-whp && cmake --build --preset x64-whp
```

x64 targets via Unicorn (any host):

```
cmake --preset x64 && cmake --build --preset x64
```

ARM64 targets via Unicorn (any host):

```
cmake --preset arm64 && cmake --build --preset arm64
```

# License

This project uses the GPL-2.0 license.
