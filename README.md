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
- Support for registering exception handlers
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

<img width="1779" height="805" alt="image" src="https://github.com/user-attachments/assets/c787e2a0-2e0f-402a-a68b-5fa60c46168b" />

No "MochiLdr.dll" DLL loaded:

<img width="700" height="902" alt="image" src="https://github.com/user-attachments/assets/73cdc8fc-8a6c-4740-9861-c0ea2e6db93c" />

## Credits

```
Paul Ungur (5pider) - https://github.com/Cracked5pider/KaynLdr
Stephen Fewer - https://github.com/stephenfewer/ReflectiveDLLInjection
Bobby Cooke - https://github.com/boku7/BokuLoader
MaldevAcademy - https://maldevacademy.com/
```
