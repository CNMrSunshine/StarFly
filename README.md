# 飞星注入器 StarFly Injector v4.0 alpha

> **仍在开发阶段 暂不考虑公开发布 可自行下载源码编译使用**

## 免责声明 ⚠️
本项目**仅供技术研究与学习使用**  
因使用本项目产生的一切非法行为 后果由使用者自行承担 开发者不负任何责任

## 编译方式

### Step1: 注入器去特征化
执行**designaturing.py**脚本 该脚本会自动完成
- 随机化ChaCha20常量和key
- 随机化目标函数和傀儡函数映射
- 使用新的常量和key加密Shellcode

**想使用自己的 Shellcode？**  
直接修改脚本中的`shellcode`数组即可

**强烈建议保留第一行Loader**（用于防止Shellcode被重复执行）

### Step2: 选择构建配置进行编译
| 配置名称   | 说明                              | 二进制体积（不含 Shellcode） | 推荐场景                  |
|------------|-----------------------------------|------------------------------|---------------------------|
| **X3**     | 正常发布版                        | ~11 KB                       | 大多数使用场景          |
| **XD**     | 带详细调试输出                    | 稍大                         | 调试/开发时使用           |
| **minimal**| 极致符号精简 关闭栈保护（/GS-） | ~9 KB                        | 追求极致体积优化（可能降低免杀率） |

## 战绩
- **X3 正常构建**：VirusTotal 静态检测 ≤ 4/72（多数情况2/72 甚至0/72）
- 注入**无恶意行为**的Shellcode：微步云沙箱 AnyRun沙箱均判定**无威胁 0/100**
- 飞星v3.0以来以**绕过卡巴斯基EDR基础版**为基准目标
- 卡饭论坛可查 v3.0/v3.1/v3.4 历史测试帖

## 注意事项
本项目展示了**用户态**高级免杀技术 但是以下防护**无法绕过**

基于CPU虚拟化和内核态Hook的防护 如360核晶

移除所有句柄VM_Write权限的防护 如iDefender

## 技术详解
### [魔改Syswhisper3 动态解析系统调用号和syscall指令地址](https://github.com/CNMrSunshine/StarFly/blob/master/SSN-Resolve.c)
不再在内存中长期存储数据 移除多平台支持 精简代码 有效对抗针对SW3特征的内存扫描

### [自研栈欺骗方案](https://github.com/CNMrSunshine/StarFly/blob/master/StackSpoof.c)
以`Kernel32!GetFileAttribute`作为傀儡函数 调用`ZwWriteVirtualMemory`系统调用为例

- Step.1 解引用野指针 引发内存访问冲突 通过VEH修改DrX寄存器 在`ZwQueryInformationFile` `syscall`指令处设置硬件断点
- Step.2 调用`GetFileAttribute` 触发硬件断点 劫持执行流到VEH
- Step.3 重设系统调用号和调用参数 恢复执行流 同时保留了从`GetFileAttribute`到`ZwQueryInformationFile`的合法调用栈

### [ChaCha20变体 解密Shellcode](https://github.com/CNMrSunshine/StarFly/blob/master/ChaCha20.c)
位运算实现ChaCha20变体解密 自定义常量抹除标准ChaCha20特征

**注意: 安全软件仍可能识别到高熵数据 或将ChaCha20变体解密判断为xor解密** 如Zen Sandbox

### [句柄提权漏洞](https://github.com/CNMrSunshine/StarFly/blob/master/utils.c)
利用[SysmonEnte](https://github.com/codewhitesec/SysmonEnte)公开的内核逻辑漏洞

打开目标进程低权限句柄 再权限提升至PROCESS_ALL_ACCESS 有效对抗内核对象创建回调

**安全软件可能阻止复制敏感进程PROCESS_ALL_ACCESS句柄 即使源句柄和目标句柄都属于注入器本身**

### [VEH注入 劫持目标进程执行流](https://github.com/CNMrSunshine/StarFly/blob/master/injector.c)
VEH注入PoC来源: [VectoredExceptionHandling](https://github.com/passthehashbrowns/VectoredExceptionHandling)

本地解析VEH链表结构体地址 模拟`RtlAddVectoredExceptionHandler`行为 向目标进程explorer.exe注入VEH

explorer.exe本身会频繁抛出异常（感谢微软屎山代码） 注入VEH后几乎立刻就能捕获执行流 :3

### Shellcode Loader 的作用
- 硬编码PEB中VEH启用标志位的地址
- 劫持到执行流后立即禁用目标进程的VEH
- 保证Shellcode只执行一次 进程随后正常运行

## TO DO
暂时没有新的想法了 后面有灵感再随缘更新吧～ :3
