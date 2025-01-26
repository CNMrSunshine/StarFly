# StarFly: A C Implementation for Bypassing and Forcibly Terminating Security Software

## Disclaimer

### This project is for educational and research purposes only. Do not use it for illegal activities. The developer assumes no responsibility for any misuse.

## Proof of Concept

*   [StarFly v1.0.2 - VirusTotal 98.7% Undetected](https://www.virustotal.com/gui/file/321eef750933d188ee0a7e9a893fba33514437b3362b14bd591f8cc505e22c5b)
*   [StarFly v1.1 - VirusTotal 97.2% Undetected](https://www.virustotal.com/gui/file/d0b39e61377ceee6f7f6f2fecf527f4f4db4274a558647a589110586f2070cdb)
*   [StarFly Latest Version - Undetected by Threatbook Cloud Sandbox (Static and Dynamic Analysis)](https://s.threatbook.com/report/file/d0b39e61377ceee6f7f6f2fecf527f4f4db4274a558647a589110586f2070cdb)
*   [StarFly Latest Version - Undetected by Qianxin Tianqiong Cloud Sandbox (Behavioral Analysis)](https://sandbox.qianxin.com/tq/report/toViewReport.do?rid=d8a1acff401216f56b662295792668cc&sk=99089590)

## Usage

> ### Integrating StarFly Kernel

> Replace all `Nt*` functions with `SFNt*` functions. See the notes for details.

> ### Using StarFly Console Directly

*   `ps <process_name(optional)>`: Output all or filtered process information, supports keyword search (case-sensitive).
*   `kill <target_process_PID>`: Terminate the specified process.
*   `getsystem`: Elevate local privileges to `SYSTEM` (requires administrator privileges).
*   `getti`: Elevate local privileges to `TrustedInstaller` (requires `SYSTEM` privileges and the `TrustedInstaller` service enabled).
*   `run <absolute_path_to_executable>`: Launch the specified executable.
*   `lang`: Switch language (English/Simplified Chinese).

## Principles

> ### StarFly Kernel

*   **Indirect System Calls:** Redirect the execution flow twice to the target `Nt*` function, forging a complete call chain while overwriting call parameters to achieve indirect system calls.
*   **Dynamic System Call Resolution:** Utilize PEB addressing to dynamically resolve `NtDll.dll`, obtaining the system call address and system call number of `Nt*` functions.
*   **Function Call Interception:** Modify the thread context to access debug registers without debug privileges, set hardware breakpoints, and perform seamless hooking of the execution flow.
*   **Function Call Redirection:** The vector exception handler captures breakpoint single-step exceptions, hijacking the execution flow and modifying RIP.
*   **Function Call Injection:** Follow the `_FastCall` calling convention, set up relevant registers and stack for parameter passing, and pass actual parameters.

> ### StarFly Modules

*   `SFListProcess`: Calls `NtQuerySystemInformation` to enumerate and filter process information.
*   `SFKillProcess`: Calls `NtTerminateProcess` to terminate the specified process.
*   `SFLocalPrivilege`: Automatically scans accessible system processes, steals and duplicates their primary and impersonation tokens.
*   `SFCreateProcess`: Calls `NtCreateUserProcess` to create a process with the specified image.
*   `SFCreateProcess2`: **Currently unimplemented** process launching solution. Calls `NtCreateProcessEx` to create an empty process, `NtCreateSection` and `NtMapViewOfSection` to load the executable image into the target process. Uses `NtReadVirtualMemory` to parse DOS and NT file headers, calculate and find the entry point. **However, an unexpected and difficult-to-fix error occurred when calling `NtCreateThreadEx` to create a thread.**
*   `SFGetTrustedInstaller`: Automatically scans `TrustedInstaller.exe`, steals and duplicates its primary and impersonation tokens.
*   `SFRespawn`: Restarts the StarFly console with the duplicated primary token.

## Notes & Known Bugs

### VS2022 Compilation Command Line

#### It is recommended to use the provided command line to compile StarFly, otherwise, bypassing security software is not guaranteed.

**C/C++:** [/permissive- /GS /Qpar /W3 /Gy /Zc:wchar_t /Gm- /O1 /sdl /Zc:inline /fp:precise /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /errorReport:prompt /WX- /Zc:forScope /std:clatest /Gr /Oi /MD /std:c++latest /FC /EHsc /nologo /diagnostics:column]

**Linker:** [/OUT:"your_output_path" /MANIFEST /NXCOMPAT /DYNAMICBASE "ntdll.lib" "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib" /MACHINE:X64 /OPT:REF /SUBSYSTEM:CONSOLE /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" /OPT:NOICF /ERRORREPORT:PROMPT /NOLOGO /TLBID:1]

*   StarFly does not generate network traffic. Some cloud sandboxes detect normal data exchange between Windows and Microsoft cloud servers.
*   Do not include `winterl.h`. The `nt.h` provided by StarFly comes from the `ProcessHacker` library and `SysWhisper3`, which already includes all necessary definitions for low-level calls.
*   **BUG:** When the compiler does not enable `/ZI` (used for compiling and generating debug information libraries), some `SFNt*` functions with 6 or more parameters will trigger an access violation exception after kernel execution. The address is the memory area filled by the function. A solution has not been found yet, and the exception is temporarily ignored using an exception handler.

## Future Plans

### Achieve session isolation bypass to terminate processes in Session 0 (including security software daemons).

## Referenced Projects

*   [SysWhisper3](https://github.com/klezVirus/SysWhispers3)
*   [Capt-Meelo's PoC](https://github.com/capt-meelo/NtCreateUserProcess)
