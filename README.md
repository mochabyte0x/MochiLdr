# MochiLdr

MochiLdr is a reflective x64 loader written in C/ASM

## Features

- Erase of DOS Header after new memory allocation
- Position Independant Code
- CRT Free
- Use of direct syscalls
- Custom implementation of
    - GetProcAddress
    - GetModuleHandle
- Support for handling TLS callbacks
- Support for registern exception handlers
- API hashing (jenkins-oaat)

No injector because I want to keep mine private. Just use the one from KaynLdr or make your own.

## APIs used

- ntdll.dll
    - NtALlocateVirtualMemory
    - NtProtectVirtualMemory
    - NtFlushInstructionCache
    - LdrLoadDll
- kernel32.dll
    - RtlAddFunctionTable

## Credits

```
Paul Ungur (5pider) - https://github.com/Cracked5pider/KaynLdr
Stephen Fewer - https://github.com/stephenfewer/ReflectiveDLLInjection
Bobby Cooke - https://github.com/boku7/BokuLoader
MaldevAcademy - https://maldevacademy.com/
```