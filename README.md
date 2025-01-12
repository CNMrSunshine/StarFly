# 飞星StarFly：基于双重硬件断点的间接系统调用实现

## 项目简介
**飞星StarFly** 是一个利用 Windows 高层 API 实现双重硬件断点 Hook 的 C 语言项目。通过修改异常处理器中的寄存器值并重定向函数调用，本项目实现了对 Windows 系统的底层间接系统调用，可用于绕过部分高级威胁检测 (AV/EDR)。

### 免责声明
本项目仅供**学习**与**技术交流**使用，请勿用于任何非法用途。开发者对此引发的任何直接或间接后果概不负责。

### 注意事项
- 本项目仍处于开发阶段，部分功能尚未实现。
- 当前版本主要实现部分核心功能，支持所有 `Nt` 函数的间接调用。

## 已实现功能
通过双重硬件断点 (DR0 和 DR1)，结合异常处理机制，StarFly 能够实现对 Windows 系统调用的重定向，具体功能如下：
1. **获取硬件断点设置点**：通过 `GetProcAddress` 动态获取高层函数（如 `GetSystemTime()`）的入口地址。
2. **获取系统调用地址**：通过 PEB 寻址，定位目标底层 NT 函数（如 `NtQuerySystemTime()`）的系统调用 (syscall) 地址。
3. **硬件断点 Hook**：
    - 在高层函数 `GetSystemTime()` 入口和 `NtQuerySystemTime()` 的系统调用地址处设置硬件断点（DR0 和 DR1）。
    - 利用异常处理器重定向实现完整调用链，通过寄存器修改与参数覆写，间接调用任意 Windows 系统底层 API。

### 技术调用链流程
GetSystemTime (已 Hook) -> NtQuerySystemTime (已 Hook) -> Syscall

### 操作流程
1. 调用 `GetSystemTime`，触发 DR0 硬件断点。
2. 异常向量处理器 (VEH) 捕获异常：
   - 修改 RIP，将调用重定向到 `NtQuerySystemTime`。
3. 调用 `NtQuerySystemTime` 时，触发 DR1 硬件断点。
4. 异常处理器再次捕获异常：
   - 修改相关寄存器值和函数参数，并最终重定向到其他底层系统调用地址。

### 未来计划
- 控制台中加入更多模组

---
