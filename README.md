# 飞星注入器（StarFly Injector）

**飞星注入器（StarFly Injector）** 是一个基于 C 语言开发的 Explorer.exe Shellcode 注入器

本项目旨在展示一种创新的注入技术 适用于安全研究和渗透测试场景 请确保在合法授权的环境下使用本工具

---

## 使用方法
### Step.1 用InjectorDesignaturing\designaturing.py 生成新的C文件
- 你可以在该脚本中 将Shellcode改为你自己的Shellcode
  - 建议Shellcode具有代码自修改功能 能将自身机器码第一位改为`ret` 以避免Shellcode被重复执行
- ChaCha20密钥 nonce和state将会重设为随机值
- 傀儡函数也会被随机设置 程序的函数调用顺序和程序结构将会改变

### Step.2 用VS2022打开项目文件 用Release配置生成解决方案
- 程序中硬编码了`*NullPointer = 1;`的汇编码长度为6 如需修改编译器优化设置 请修改此值

## 项目特点

- **利用VEH和硬件断点实现的无痕堆栈欺骗+间接系统调用方案**：[详情见项目 GalaxyGate](https://github.com/cnmrsunshine/galaxygate)
- **句柄提权漏洞利用**：仅调用底层 `Nt*` 函数 利用[SysmonEnte](https://github.com/codewhitesec/SysmonEnte)中使用的内核逻辑漏洞
- **ChaCha20加密Shellcode**: 通过原始内存操作实现 不依赖第三方库
- **远程VEH注入**: 修改VEH链表劫持执行流 改自[passthehashbrowns的Github项目](https://github.com/passthehashbrowns/VectoredExceptionHandling/)

---

## 环境要求
- **操作系统**：Windows 10/11（**x64**）

## 引用与致谢

本项目部分代码和技术灵感来源于以下开源项目，在此表示感谢：

- **[SysWhispers3](https://github.com/klezVirus/SysWhispers3)**：提供系统调用号和调用地址解析功能
- **[ThreadlessInject-C-Implementation](https://github.com/lsecqt/ThreadlessInject-C-Implementation)**：无线程注入技术的参考实现 （旧版StarFly）
- **[SysmonEnte](https://github.com/codewhitesec/SysmonEnte)**：句柄提权漏洞来源
- **[Native API Header](https://github.com/winsiderss/phnt)**： 非常感谢SystemInformer项目对底层开发者的帮助和支持
- **[Silent Moon Walk](https://github.com/klezVirus/SilentMoonwalk)**: GalaxyGate的初始灵感来源
- **[VectoredExceptionHandling](https://github.com/passthehashbrowns/VectoredExceptionHandling/)**: VEH注入相关思路和函数来源
