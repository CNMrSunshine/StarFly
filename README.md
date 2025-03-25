# 飞星注入器（StarFly Injector）

**飞星注入器（StarFly Injector）** 是一个基于 C 语言开发的 Windows 系统注入工具，利用硬件断点与 VEH（向量异常处理）的组合实现了“动态堆栈欺骗”（Dynamic Stack Spoofing）技术，并结合无线程注入（Threadless Injection）和句柄提权漏洞，成功将自定义 shellcode 注入到 `winlogon.exe` 进程中。注入完成后，通过任意方式触发 UAC（用户账户控制）即可启动计算器（`calc.exe`），作为注入成功的演示。

本项目旨在展示一种创新的注入技术，适用于安全研究和渗透测试场景。请确保在合法授权的环境下使用本工具。

---

## 项目特点

- **动态堆栈欺骗（Dynamic Stack Spoofing）**：通过硬件断点和 VEH 修改调用堆栈，伪装系统调用以绕过检测。
- **无线程注入（Threadless Injection）**：无需创建新线程，利用现有系统调用（如 `NtWaitForSingleObject`）触发 payload。
- **句柄提权漏洞利用**：通过句柄提升技术获取对 `winlogon.exe` 的完全访问权限。
- **目标进程**：注入 `winlogon.exe`，一个高权限系统进程。
- **触发机制**：注入后，通过触发 UAC（例如运行需要提升权限的程序）启动计算器。

---

## 技术原理

### 1. 动态堆栈欺骗（Dynamic Stack Spoofing）
- 使用硬件断点（通过调试寄存器 `Dr0` 和 `Dr7`）在“傀儡”高层函数间接调用的 `Nt*` 函数 `Syscall` 指令处设置断点。
- 当断点触发时，通过自定义的 VEH（`ExceptionHandler`）接管异常处理，修改寄存器和堆栈内容。
- 将真实的系统调用参数传递给内核，同时不破坏原有调用栈，防止被安全软件检测。

### 2. 无线程注入（Threadless Injection）
- 在目标进程（`winlogon.exe`）中寻找合适的内存空洞（Memory Hole），分配可执行内存。
- 将 shellcode（包含加载器和计算器启动代码）写入内存，并通过修改目标函数（如 `NtWaitForSingleObject`）的指令为 `call`，跳转至 shellcode。
- 当系统调用被触发时（例如 UAC 触发 `winlogon.exe` 的活动），shellcode 被执行。

### 3. 句柄提权
- 通过 `ConvertProcNameToPid` 定位 `winlogon.exe` 的 PID。
- 使用 `LocalPrivilege` 函数模拟 `SYSTEM` 权限，使线程与 `winlogon.exe` 为同一用户所有（句柄提权漏洞触发要求）
- 调用 `ElevateHandle` 提升句柄权限，获取对 `winlogon.exe` 的完全访问权（`PROCESS_ALL_ACCESS`）。

### 4. Shellcode 执行
- Shellcode 包含两部分：
  - **加载器（shellcode_loader）**：恢复被Hook处的原始指令。
  - **计算器 payload（shellcode）**：从 `kernel32.dll` 中解析 `WinExec`，调用 `calc.exe`。
- 当 `NtWaitForSingleObject` 被调用时，Hook被触发，最终弹出计算器。

---

## 功能

- **注入目标**：`winlogon.exe`
- **触发方式**：任意触发 UAC（例如运行需要管理员权限的程序）
- **效果**：成功注入后弹出计算器窗口（`calc.exe`）

---

## 使用方法

### 环境要求
- **操作系统**：Windows 10/11（64 位）
- **编译器**：GCC 或 MSVC2022 (MSVC C标准库 静态链接易报毒）
- **依赖头文件**：
  - `windows.h`
  - `stdio.h`
  - `stdint.h`
  - `syscalls.h`（Syswhisper3生成）
  - `nt.h`（NT 内部结构定义 源于https://github.com/winsiderss/phnt）


### 运行步骤
1. 以管理员权限运行 `StarFly.exe`。
2. 程序将自动：
   - 定位并提升对 `winlogon.exe` 的权限。
   - 注入 shellcode。
   - 输出注入过程的日志。
3. 注入完成后，运行任意需要 UAC 提升的程序。
4. 检查是否弹出计算器窗口，验证注入成功。

---

## 注意事项

- **权限要求**：必须以管理员权限运行程序，否则无法提升对 `winlogon.exe` 的访问权限。
- **安全性**：本工具仅用于教育和研究目的，请勿在未经授权的系统上使用。
- **待修复**: 本项目暂未实现模拟ImpersonateLogedOnUser的底层实现，调用该函数易被检测。

---

## 示例输出
```
[+] WinLogon PID Found: 1234
[+] Hook Address: 0x00007FF8ABCD1234
[+] Memory allocated at: 0x00007FF8DCBA4321
[+] Original bytes at 0x00007FF8ABCD1234: 0x1234567890ABCDEF
[+] Memory protection changed to RWX at 0x00007FF8ABCD1234
[+] Call instruction written at 0x00007FF8ABCD1234, pointing to 0x00007FF8DCBA4321
[+] payloadSize: 128
[+] Payload written to 0x00007FF8DCBA4321
[+] Payload memory protection set to RX
[+] Injection successful, waiting for NtWaitForSingleObject to trigger!
```

---

## 代码结构

- **`main`**：主函数，协调权限提升、内存分配和注入流程。
- **`ExceptionHandler`**：VEH 处理函数，负责硬件断点触发后的堆栈欺骗。
- **`SFNt*`**：一系列封装的 NT 系统调用，用于底层操作。
- **`ConvertProcNameToPid`**：根据进程名查找 PID。
- **`LocalPrivilege`**：模拟 SYSTEM 权限。
- **`ElevateHandle`**：提升句柄权限。
- **`FindMemoryHole`**：寻找内存空洞。
- **`GenerateHook`**：生成跳转 hook。
- **`shellcode_loader` 和 `shellcode`**：注入的机器码。

---

## TO DO LIST

- [x] 降低敏感可打印字符辨识度 
- [ ] 用 `NtDuplicateToken` + `NtSetInformationThread` 实现 `ImpersonateLoggedOnUser
- [ ] 用 `WindowsAPI` 实现C标准库部分功能
- [ ] 为 `NtReadProcessMemory` `NtWriteProcessMemory` `NtProtectVirtualMemory` 更新 `AdvDSS`
- [ ] 更新 `Shellcode`
- [ ] 重设注入点 将Hook设置在进程主映像

---

## 引用与致谢

本项目部分代码和技术灵感来源于以下开源项目，在此表示感谢：

- **[SysWhispers3](https://github.com/klezVirus/SysWhispers3)**：提供了系统调用生成和地址解析功能。
- **[ThreadlessInject-C-Implementation](https://github.com/lsecqt/ThreadlessInject-C-Implementation)**：无线程注入技术的参考实现。
- **[SysmonEnte](https://github.com/codewhitesec/SysmonEnte)**：句柄提权技术的灵感来源。
- **[Native API Header](https://github.com/winsiderss/phnt)**： 非常感谢 `SystemInformer / ProcessHacker` 项目对底层开发者的帮助和支持。

