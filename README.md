# 飞星StarFly-NextGen: 免杀并反杀AV/EDR的C语言实现

## 免责声明

本项目仅供学习和交流使用。若用于非法用途，开发者不承担任何责任。

## 注意事项

该项目目前仍处于开发阶段，部分功能尚未实现，并且可能存在未知错误。

## 项目概述

本项目通过使用硬件断点Hook，底层寄存器修改和底层系统调用技术，实现对杀毒软件（AV）和高级端点检测与响应（EDR）系统的绕过和反杀。具体实现思路如下：

1. **SysWhisper3的使用**：通过SysWhisper3获取`ntdll.dll`中所需底层API的系统调用地址。

2. **函数地址解析**：解析`GetSystemTime`和`NtQuerySystemTime`的函数地址。

3. **硬件断点设置**：对上述两个函数的地址设置硬件断点。

4. **间接系统调用链**：
   - 调用`GetSystemTime`时，硬件断点被触发。
   - 向量异常处理器（VEH）捕获单步异常，通过修改RIP将调用指向`NtQuerySystemTime`。
   - `NtQuerySystemTime`触发硬件断点。
   - 异常处理器再次捕获异常，通过修改RIP将调用指向真实调用的底层API对应的Syscall地址。

### 流程


GetSystemTime(Hooked) -> NtQuerySystemTime(Hooked) -> Syscall


## 待实现功能

- **间接调用`NtQuerySystemInformation`**：用于枚举系统进程。
- **本地权限提升**：
  - 查找无保护的System进程。
  - 间接调用`NtOpenProcess`打开句柄。
  - 窃取目标进程的模拟令牌以获得System权限。
- **AV/EDR进程反杀**：
  - 从进程表中找到AV/EDR相关进程的PID。
  - 间接调用`NtOpenProcess`打开句柄。
  - 间接调用`NtTerminateProcess`结束进程。
  - 间接调用`NtClose`关闭句柄。

## 存在问题

当前使用SysWhisper3解析到的Syscall地址为0，后续将尝试替换为SysWhisper2。
