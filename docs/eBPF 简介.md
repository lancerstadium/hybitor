# eBPF 简介

> **参考链接 :**

[What is eBPF? An Introduction and Deep Dive into the eBPF Technology](https://ebpf.io/what-is-ebpf/)

[eBPF基础_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1K34y1P7mg)

[GitHub - eunomia-bpf/bpf-developer-tutorial: Learn eBPF by examples | eBPF 开发者教程与知识库：通过小工具和示例一步步学习 eBPF，包含性能、网络、安全等多种应用场景](https://github.com/eunomia-bpf/bpf-developer-tutorial)

[高效入门eBPF_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1LX4y157Gp)

[](http://static.sched.com/hosted_files/osseu19/5f/unified-tracing-platform-oss-eu-2019.pdf)

[Linux Tracing System浅析 & eBPF开发经验分享_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV17t4y1x7kV)

[在 WSL2 环境下安装 BPF 工具链 | 时间之外，地球往事](https://oftime.net/2021/01/16/win-bpf/)

[eBPF基础_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1K34y1P7mg/?spm_id_from=333.788.recommend_more_video.0&vd_source=a46aee5caa4e010c950debd43a109188)

- > [https://blog.csdn.net/baidu_29900103/article/details/133852912](https://blog.csdn.net/baidu_29900103/article/details/133852912)
- > ssssss

---

---

# 1 eBPF 是什么

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image.png)

eBPF （Extended Berkeley Packet Filter）是可以在内核虚拟机中运行的程序，不需要更改内核源码或加载内核模块，动态安全的拓展内核功能。

1. eBPF 是一个：内核虚拟机、运行时沙盒、受限编程语言；
2. eBPF 之于 Linux Kernel，相当于 JS 之于 Web；
3. eBPF 是在 BPF 基础上的拓展增强；

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(2).png)

> 关于 BPF :

- > 是伯克利包过滤（Berkeley Packet Filter）的简写；
- > BPF现在一般叫做 cBPF（Classic BPF），eBPF 现在一般叫做 BPF ；
- > 允许 User 程序链接到网络套接字，进行过滤筛选；
- > 网络抓包工具： `tcpdump` 和 `wireshark` 就是 cBPF 的经典案例；
- > eBPF现在被认为是一个独立的术语，与 cBPF 关系不大。

---

# 2 eBPF 能做什么

应用领域：

- 网络：在现代数据中心和云原生环境中提供高性能网络和负载平衡；
- 安全：以低开销提取细粒度的安全可观测性数据；
- 性能监测：跟踪应用程序、排障，监测程序或容器运行时；
- 可视化：可视化内核相关事件指标。

## 2.1 事件 Events

- **数据源**（Data Source）：提供数据的来源。
- **事件**（Events）：数据源产生数据的一系列行为。

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(3).png)

## 2.2 追踪 Tracing

- **Tracing 内核框架**：负责对接数据源，采集解析发送数据，对用户态提供接口。
- **Tracing 前端工具**：对接 Tracing 内核框架，直接与用户交互，负责数据采集、配置、数据。

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(4).png)

## 2.3 数据源探针

### 2.3.1 硬件探针

- **硬件探针**（HPC, Hardware Performance Counter）：是CPU硬件提供的功能，它能够监控CPU级别的事件，比如执行的指令数，跳转指令数，Cache Miss等等，被广泛用于性能调试（Vtune, Perf）、攻击监测等等。

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(5).png)

- `perf stat` 使用 HPC 采集数据：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(6).png)

- LBR（Last Branch Record）是硬件提供的另一种特性，能够::记录每条分支（跳转）指令的源地址和目的地址::。基于LBR硬件特性，可实现调用栈信息记录。基于 LBR 特性可生成火焰图（Flame Graph）。

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(7).png)

> 备注：使用`perf record -F 99 -a --call-graph lbr` 收集数据，火焰图与用户之间有较大的语义鸿沟。

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(8).png)

### 2.3.2 软件探针对比

- 通过静态探针（tracepoint: sched_process_exec）监控进程执行二进制文件的行为：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(9).png)

- 通过动态探针（kprobe: exec_binprm）监控进程执行二进制文件的行为：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(10).png)

- 另一个终端上的输入：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(11).png)

- 对比：::eBPF尝试结合两者优势::

|        | 静态探针              | 动态探针              |
| ------ | ----------------- | ----------------- |
| 代表     | Kernel Tracepoint | Kprobe            |
| 性能     | 好                 | 相对较差              |
| 稳定性    | 稳定                | 不稳定（函数变更可能导致程序失效） |
| 修改内核代码 | 需要                | 不需要               |
| 探针数量   | 支持静态探针数量有限        | 可以Hook几乎所有内核函数    |

- Tracing 内核框架对比：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(12).png)

- eBPF与内核模块对比：

| **维度**              | **Linux 内核模块**      | **eBPF**                     |
| ------------------- | ------------------- | ---------------------------- |
| kprobes/tracepoints | 支持                  | 支持                           |
| **安全性**             | 可能引入安全漏洞或导致内核 Panic | 通过验证器进行检查，可以保障内核安全           |
| 内核函数                | 可以调用内核函数            | 只能通过 BPF Helper 函数调用         |
| 编译性                 | 需要编译内核              | 不需要编译内核，引入头文件即可              |
| 运行                  | 基于相同内核运行            | 基于稳定 ABI 的 BPF 程序可以编译一次，各处运行 |
| 与应用程序交互             | 打印日志或文件             | 通过 perf_event 或 map 结构       |
| 数据结构丰富性             | 一般                  | 丰富                           |
| **入门门槛**            | 高                   | 低                            |
| **升级**              | 需要卸载和加载，可能导致处理流程中断  | 原子替换升级，不会造成处理流程中断            |
| 内核内置                | 视情况而定               | 内核内置支持                       |

---

# 3 eBPF 如何工作

## 3.1 eBPF 虚拟机

eBPF 虚拟机和系统虚拟化（如kvm）有着本质不同：

- 系统虚拟化基于 x86 或 arm64 等通用指令集，足以完成完整计算机的所有功能。
- eBPF 只提供有限的指令集，用于完成一部分内核功能，远不足以模拟完整的计算机。

eBPF 分为用户空间程序和内核程序两部分：

- 用户空间程序负责加载 BPF 字节码至内核，如需要也会负责读取内核回传的统计信息或者事件详情；
- 内核中的 BPF 字节码负责在内核中执行特定事件，如需要也会将执行的结果通过 maps 或者 perf-event 事件发送至用户空间；

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(13).png)

## 3.2 eBPF 模块

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(14).png)

1. **eBPF 辅助函数：**它提供了一系列用于 eBPF 程序与内核其他模块进行交互的函数。这些函数并不是任意一个 eBPF 程序都可以调用的，具体可用的函数集由 BPF 程序类型决定。
2. e**BPF 验证器（Verifier）：它**用于确保 eBPF 程序的安全。验证器会将待执行的指令创建为一个有向无环图（DAG），确保程序中不包含不可达指令；接着再模拟指令的执行过程，确保不会执行无效指令。

   > 静态验证：类似静态分析，主要做边界检查，防止内存访问越界。

1. **eBPF 存储模块：**是由 ::11 个 64 位寄存器、一个程序计数器和一个 512 字节的栈::组成。这个模块用于控制 eBPF 程序的执行。

   > 关于eBPF存储模块的寄存器：

   - > R0 寄存器用于存储函数调用和 eBPF 程序的返回值，这意味着函数调用最多只能有一个返回值；
   - > R1-R5 寄存器用于函数调用的参数，因此函数调用的参数最多不能超过 5 个；
   - > R10 是一个只读寄存器，用于从栈中读取数据。
1. **即时编译器（JIT）：**将 eBPF 字节码编译成本地机器指令，以便更高效地在内核中执行。
2. **BPF 映射（map）：**用于提供大块的存储。这些存储可被用户空间程序用来进行访问，进而控制 eBPF 程序的运行状态。

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(15).png)

---

# 4 eBPF 程序编写

## 4.1 eBPF程序分类

- 内核代码（Kernel code）：经过编译器（LLVM）编译为eBPF字节码，使用eBPF JIT加载到内核执行。目前大部分工具使用C编写，包括BCC和libbpf。

   > 备注：bpftrace提供一种易用脚本高效 tracing ，原理是用 LLVM 将脚本转化为 eBPF 字节码。

- 用户代码（User code）：负责与eBPF Map 交互，接收 eBPF 内核程序发送的数据。本质是通过 Linux 提供的 syscall 完成的，可以用任何语言实现。如：BCC → python，libbpf → c/cpp，tracee → go。

> eBPF使用：bpftrace, BCC(python), ply

> eBPF开发：libbpf

## 4.2 代码示例

- `hello.bpf.c` ：内核程序

```cpp
/// \file: hello.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Insert section 1: 指定 license，用于 verify.
char LICENSE[] SEC("license") = "Dual BSD/GPL";
// Insert section 2: 在 do_sys_open 入口放置 kprobe 探针
// 系统调用进入触发：打印信息
SEC("tracepoint/syscalls/sys_enter_execve")
int BPF_PROG()
{
  char msg[] = "Hello, World!";
  bpf_trace_printk(msg, sizeof(msg));
  return 0;
}
```

`hello.c` ：用户程序

```cpp
/// \file: hello.c
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"

static int libbpf_print_fn(
  enum libbpf_print_level level,
  const char *format,
  va_list args) 
{
  return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
  struct rlimit rlim_new = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };
  if(setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

int main(int argc, char **argv)
{
  struct hello_bpf *skel;
  int err;
  // 设置 libbpf error 和 debug 信息回调
  libbpf_set_print(libbpf_print_fn);
  // 放松内存限制
  bump_memlock_rlimit();
  // 打开 BPF 应用
  skel = hello_bpf__open();
  if(!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }
  // 加载验证 BPF 程序
  err = hello_bpf__load(skel);
  if(err) {
    fprintf(stderr, "Faied to load and verify BPFskeleton\n");
    goto cleanup;
  }
  // 绑定tracepoint handler
  err = hello_bpf__attach(skel);
  if(err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
         "to see out put of the BPF programs.\n");
  for(;;) {
    // 启动 BPF 程序板机
    fprintf(stderr, ".");
    sleep(1);
  }
cleanup:
  hello_bpf__destroy(skel);
  return -err;
}
```

- 编译运行：

```shell
cmake .
make hello
sudo ./hello
```

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(16).png)

---

# 5 eBPF未来

- BCC
- libbpf
- CO-RE（Compile Once, Run Everywhere）

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(17).png)

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(18).png)

问题：

- 移植性差，依赖内核版本
- 每次运行都需要编译
- 依赖大：Clang/LLVM + Linux headers
- 资源消耗多：Clang/LLVM编译消耗CPU/内存

---

# 附件

附件1. 数据源与内核框架映射：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(19).png)

附件2. BPF架构原理图：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(20).png)

附件3. eBPF架构图（另一种视角）：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(21).png)

附件4. eBPF拓展&基础设施：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(22).png)

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(23).png)

附件5. eBPF指令集：

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(24).png)

![Image.png](eBPF%20%E7%AE%80%E4%BB%8B.assets/Image%20(25).png)

---

