---

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
- 使用硬件断点（通过调试寄存器 `Dr0` 和 `Dr7`）在目标系统调用（如 `NtWaitForSingleObject`）处设置断点。
- 当断点触发时，通过自定义的 VEH（`ExceptionHandler`）接管异常处理，动态修改寄存器和堆栈内容。
- 将真实的系统调用参数传递给内核，同时伪装调用栈，防止被安全软件检测。

### 2. 无线程注入（Threadless Injection）
- 在目标进程（`winlogon.exe`）中寻找合适的内存空洞（Memory Hole），分配可执行内存。
- 将 shellcode（包含加载器和计算器启动代码）写入内存，并通过修改目标函数（如 `NtWaitForSingleObject`）的指令为 `call`，跳转至 shellcode。
- 当系统调用被触发时（例如 UAC 触发 `winlogon.exe` 的活动），shellcode 被执行。

### 3. 句柄提权
- 通过 `ConvertProcNameToPid` 定位 `winlogon.exe` 的 PID。
- 使用 `LocalPrivilege` 函数模拟 `SYSTEM` 权限，结合 `ElevateHandle` 提升句柄权限，获取对 `winlogon.exe` 的完全访问权（`PROCESS_ALL_ACCESS`）。

### 4. Shellcode 执行
- Shellcode 包含两部分：
  - **加载器（shellcode_loader）**：保存原始指令并跳转至实际 payload。
  - **计算器 payload（shellcode）**：从 `kernel32.dll` 中解析 `WinExec`，调用 `calc.exe`。
- 当 `NtWaitForSingleObject` 被调用时，跳转至 shellcode，最终弹出计算器。

---

## 功能

- **注入目标**：`winlogon.exe`
- **触发方式**：任意触发 UAC（例如运行需要管理员权限的程序）
- **效果**：成功注入后弹出计算器窗口（`calc.exe`）

---

## 使用方法

### 环境要求
- **操作系统**：Windows 10/11（64 位）
- **编译器**：MSVC（推荐 Visual Studio 2019 或更高版本）
- **依赖头文件**：
  - `windows.h`
  - `stdio.h`
  - `stdint.h`
  - `syscalls.h`（自定义系统调用头文件）
  - `nt.h`（NT 内部结构定义）

### 编译步骤
1. 克隆或下载本项目代码。
2. 确保 `syscalls.h` 和 `nt.h` 已正确配置（可参考 `SysWhispers3` 项目生成）。
3. 使用 Visual Studio 或其他支持 MSVC 的 IDE 打开项目。
4. 设置编译目标为 `x64 Release`。
5. 编译生成 `StarFlyInjector.exe`。

### 运行步骤
1. 以管理员权限运行 `StarFlyInjector.exe`。
2. 程序将自动：
   - 定位并提升对 `winlogon.exe` 的权限。
   - 注入 shellcode。
   - 输出注入过程的日志。
3. 注入完成后，运行任意需要 UAC 提升的程序（例如 `cmd.exe /c dir`）。
4. 检查是否弹出计算器窗口，验证注入成功。

---

## 注意事项

- **权限要求**：必须以管理员权限运行程序，否则无法提升对 `winlogon.exe` 的访问权限。
- **安全性**：本工具仅用于教育和研究目的，请勿在未经授权的系统上使用。
- **稳定性**：注入可能会因系统版本差异或安全补丁而失败，请在测试环境验证。
- **日志输出**：程序运行时会输出关键步骤的地址和状态，便于调试。

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

## 引用与致谢

本项目部分代码和技术灵感来源于以下开源项目，在此表示感谢：

- **[SysWhispers3](https://github.com/klezVirus/SysWhispers3)**：提供了系统调用生成和地址解析功能。
- **[ThreadlessInject-C-Implementation](https://github.com/lsecqt/ThreadlessInject-C-Implementation)**：无线程注入技术的参考实现。
- **[SysmonEnte](https://github.com/codewhitesec/SysmonEnte)**：句柄提权技术的灵感来源。

---
