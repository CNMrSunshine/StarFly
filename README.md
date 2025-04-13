# 飞星注入器（StarFly Injector）

**飞星注入器（StarFly Injector）** 是一个基于 C 语言开发的 Winlogon.exe Shellcode 注入器 v2.0.2版本已成功绕过卡巴斯基 Next EDR Foundation 和 BitDefender Total Security

本项目旨在展示一种创新的注入技术，适用于安全研究和渗透测试场景。请确保在合法授权的环境下使用本工具

[详情请前往 菜叶片的博客](https://cnmrsunshine.github.io/2025/04/05/fei-xing-hua-po-ye-kong-starfly-zhu-ru-qi-shen-du-jie-xi-yu-edr-tu-fang-shi-zhan/)
---

## 项目特点

- **利用VEH和硬件断点实现的无痕堆栈欺骗+间接系统调用方案**：[详情见项目 GalaxyGate](https://github.com/cnmrsunshine/galaxygate)
- **无线程注入（Threadless Injection）**：仅调用底层 `Nt*` 函数实现的无线程注入 代码改编于[ThreadlessInject-C-Implementation](https://github.com/lsecqt/ThreadlessInject-C-Implementation)
- **句柄提权漏洞利用**：仅调用底层 `Nt*` 函数 利用[SysmonEnte](https://github.com/codewhitesec/SysmonEnte)中使用的内核逻辑漏洞
- **注入点**：通过反汇编发现的一个不影响线程正常工作的 `winlogon.exe` 注入点

---

## 技术原理

### 1. 无痕堆栈欺骗 + 间接系统调用
- 使用硬件断点（通过调试寄存器 `Dr0` 和 `Dr7`）在“傀儡”高层函数间接调用的 `Nt*` 函数 `Syscall` 指令处设置断点。
- 当断点触发时，通过自定义的 VEH（`ExceptionHandler`）接管异常处理，修改寄存器和堆栈内容。
- 将真实的系统调用参数传递给内核，同时不破坏原有调用栈，防止被安全软件检测。

### 2. 句柄提权
- 通过 `ConvertProcNameToPid` 定位 `winlogon.exe` 的 PID。
- 使用 `LocalPrivilege` 函数模拟 `SYSTEM` 权限，使线程与 `winlogon.exe` 为同一用户所有（句柄提权漏洞触发条件）
- 调用 `ElevateHandle` 提升句柄权限，获取对 `winlogon.exe` 的完全访问权（`PROCESS_ALL_ACCESS`）

### 3. 无线程注入（Threadless Injection）
- 在目标进程（`winlogon.exe`）中寻找合适的内存空洞（Memory Hole），分配可执行内存
- 将 shellcode（包含加载器和计算器启动代码）写入内存，并替换注入点的 `nop` 指令为 `call`，跳转至 shellcode
- 当执行流从 `NtWaitForSingleObject` 返回后 shellcode 被执行 且不影响线程正常工作

---

## 环境要求
- **操作系统**：Windows 10/11（目前仅支持 64 位）
- **编译器**：GCC 或 MSVC2022 (MSVC C标准库 静态链接易报毒）

---

## 注意事项

- **权限要求**：必须以管理员权限运行程序，否则无法提升对 `winlogon.exe` 的访问权限
- **安全性**：本工具仅用于教育和研究目的，请勿在未经授权的系统上使用

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

## 引用与致谢

本项目部分代码和技术灵感来源于以下开源项目，在此表示感谢：

- **[SysWhispers3](https://github.com/klezVirus/SysWhispers3)**：提供了系统调用号和调用地址解析功能
- **[ThreadlessInject-C-Implementation](https://github.com/lsecqt/ThreadlessInject-C-Implementation)**：无线程注入技术的参考实现
- **[SysmonEnte](https://github.com/codewhitesec/SysmonEnte)**：句柄提权漏洞的来源
- **[Native API Header](https://github.com/winsiderss/phnt)**： 非常感谢 `SystemInformer / ProcessHacker` 项目对底层开发者的帮助和支持
- **[Silent Moon Walk](https://github.com/klezVirus/SilentMoonwalk)**: GalaxyGate的初始灵感来源

