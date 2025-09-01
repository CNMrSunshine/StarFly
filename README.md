# 飞星注入器（StarFly Injector）

**飞星注入器（StarFly Injector）** 是一个基于 C 语言开发的 Explorer.exe Shellcode 注入器

本项目旨在展示一种创新的注入技术 适用于安全研究和渗透测试场景 请确保在合法授权的环境下使用本工具

[详情请前往 菜叶片的博客](https://cnmrsunshine.github.io/2025/04/05/fei-xing-hua-po-ye-kong-starfly-zhu-ru-qi-shen-du-jie-xi-yu-edr-tu-fang-shi-zhan/)
---

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
