# Hybitor

## 待办事项（TODO）

| 编号(number) | 模块(module) | 头文件目录(headers) | 命令(command) | 库(libs) | 完成 (finish) |
|---|---|---|---|---|---|
| 1 | 命令行 CLI | cliparser | `./hybitor -h` | CLI11_v2.3.2 | ✅ |
| 2 | 文件读写 File | binaryfile | `./hybitor [subcommand] [binary_file] -o [llvm_ir_file.ll]` | LIEF | ✅ |
| 3 | 反汇编 Disassemble | capstone | `./hybitor disassemble [binary_file]` | capstone_v5.0.0 | ✅ |
| 4 | 中间码生成 LLVM IR Generate | binaryfile | `/hybitor lift [binary_file] -o [llvm_ir_file.ll]` | retdec / HQEMU | ✅ |
| 5 | 基本块 Basic Block | basicblock | `` | llvm_v16.0.6 |  |
| 6 | 静态分析 Static Analysis |  | `` | LLVM BOLT |  |
| 7 | 中间码优化 Optimization |  | `` | LLVM Pass |  |
| 8 | 动态执行 JIT |  | `` | LLVM JIT / Instrew / QEMU |  |
| 9 | 静态编译 Compile |  | `` | LLVM Back-End |  |
| 10 | Profile support |  | `` | LLVM BOLT & Perf |  |
| 11 | Client/Server 架构 |  | `` | Instrew |  |
| 12 | 多线程 Muti Thread |  | `` | HQEMU |  |
| 13 | 自动化并行 Parallel |  | `` | LLVM Polly |  |
| 14 | 机器学习指导优化 Machine Learning |  | `` | MLGO / CompilerGym |  |




## 0 项目说明

### 0.0 背景介绍

- 二进制翻译：是一种**原指令集体系结构代码** `Source/Guest` 翻译成**目标指令集体系结构代码** `Target/Host` 的编译技术，使用该技术可以令源代码在不兼容的目标体系结构上运行。

- 二进制翻译分类：
  - 动态翻译（JIT）：翻译后获取程序动态信息进行优化，并执行程序，运行时编译优化。
  - 静态翻译（AOT）：翻译后进行静态分析，将程序链接成`Host`端可执行文件，运行前就完成了所有的编译优化工作。
  - 动态二进制翻译器（DBT, *Dynamic Binary Translator*）：[QEMU](https://www.qemu.org/), CMS, HQEMU ...
  - 动态二进制优化器（DBO, *Dynamic Bianry Optimizator*）：Mojo, DynamoRIO ...
  - 静态二进制翻译器（SBT, *Static Binary Translator*）：revng, SQEMU ...
  - 混合二进制翻译器（HBT, *Hybrid Bianry Translator*）：LLBT, Rabbit ...


- 对比编译器：
  - 传统编译：`Source` 高级语言源程序 --> `Target` 面向特定体系架构的二进制程序。
  - 二进制翻译：`Source` 源体系架构的二进制程序 --> `Target` 目标体系架构的二进制程序。

- 应用领域：
  - 解决老旧二进制代码在新处理器上的运行问题，促进指令集革新；
  - 改善处理器性能、功耗和设计复杂度；
  - 辅助体系结构研究和设计、加速软件开发。


### 0.1 项目介绍

- `Hybitor` 是一个混合二进制翻译器（*Hybird Binary Translator*）：
  - 功能：输入 `Guest` 端 ELF 可执行文件，将其静态翻译为 `LLVM IR`，输出 `Host` 端 ELF 可执行文件；
  - 依赖：`capstone-5.0.0`，`qemu-user-6.0.0`, `llvm-project-16.0.6`
  - 目标：模块化、高效率、支持多种编译优化选项、支持Profile、多线程；
  - 应用场景：让`Guest`应用程序运行在不同体系架构的`Host`端主机上。

- 其他信息：
  - 开发者: LancerStadium
  - 邮箱: lancerstadium@163.com
  - 项目仓库: https://github.com/lancerstadium/hybitor.git


- 参考资料：
  1. [nanpanjiang-project](https://github.com/hellollvm/nanpanjiang-project/)
  2. [LLBT](https://dl.acm.org/doi/10.1145/2380403.2380419)
  3. ...（待补充）


### 0.2 项目安装

1. 依赖准备：

```shell
apt install capstone5
apt install llvm-16
```

2. 链接库配置：


3. 项目构建：

```shell
mkdir build/    # 创建构建文件夹
cd build/       # 进入构建文件夹
cmake ..        # 配置 Makefile
make -j$(nproc) # 并行构建程序
make install    # 将可执行程序安装到本地
```

---


## 1 项目构建设计

### 1.1 目录结构

- C++项目目录，帮助组织和管理代码、资源和构建文件：

```
hybitor/
│
├── src/               # 存放源代码文件
│   ├── main.cpp       # 主程序入口
│   ├── module1.cpp    # 模块1的源代码
│   ├── module2.cpp    # 模块2的源代码
│   └── ...
│
├── include/           # 存放头文件
│   ├── module1.h      # 模块1的头文件
│   ├── module2.h      # 模块2的头文件
│   └── ...
│
├── lib/               # 存放第三方库文件（如果有）
│   ├── lib1.a         # 库1的二进制文件
│   ├── lib2.so        # 库2的共享库文件
│   └── ...
│
├── build/             # 存放编译生成的文件
│   ├── hybitor        # 可执行程序
│   ├── release/       # 发行版本构建目录
│   └── ...
│
├── CMakeLists.txt     # CMake构建系统配置文件（如果使用CMake）
└── README.md          # 项目文档

```

- 文件及目录说明：
  - `src/` 目录包含项目的源代码文件，通常包括主程序入口和各个模块的源代码。
  - `include/` 目录包含项目的头文件，用于声明类、函数、常量等。这些头文件通常与源文件一一对应。
  - `lib/` 目录可以用于存放第三方库文件，如果你的项目依赖于外部库。
  - `build/` 目录通常用于存放构建生成的文件，例如可执行文件和中间构建文件。这个目录是可选的，你可以根据喜好将构建文件放在其他位置。如果你使用CMake或Make等构建系统，可以在项目根目录下包含相应的构建系统配置文件（例如，CMakeLists.txt 或 Makefile）。
  - `README.md` 文件通常包含项目的简要说明、使用方法、依赖项和其他有用信息。



### 1.2 cmake 构建工具

- 项目使用`cmake`工具进行构建
- 在主目录下修改 `CMakeList.txt` 文件，可以自定义构建：



### 1.3 git 版本控制

- 项目使用`git`工具进行版本控制

```shell
git add .
git commmit -m 'your_commit_context'
git push
git tag 
```

---


## 2 二进制翻译框架设计

### 2.1 DBT 框架设计

1. 加载模块（*Load*）：解析源二进制代码，定位并加载其代码和数据内容。
2. 翻译模块（*Translate*）：把源二进制代码翻译成目标二进制代码。
3. 执行模块（*Execution*）：在动态二进制翻译系统自身执行和生成目标二进制代码执行之间的切换工作以及剖析信息的收集工作。
4. 代码缓存管理模块（*Code Cache*）：对有限大小的代码缓存进行管理，包括代码块查找、替换和重新布局等。
5. 运行时服务模块（*Server*）：负责对运行环境进行仿真，例如：对源二进制对库函数调用、系统调用和信号进行处理转换。

- 关于翻译模块设计：
  - 解释器（*Interpreter*）：翻译初始阶段采用解释器可以减小启动开销，并计数剖析程序热点区域（function or trace）；
  - 即时编译器（*JIT Complier*）：热点块达到阈值，翻译引擎开始进行翻译，生成并保存 `Target` 代码。有些阶段性编译器会在开始阶段插桩剖析代码，收集运行时信息，出现热点块时，即时编译器将利用这些信息进行优化，并在下一阶段将代码翻译成更高质量的目标二进制代码。



### 2.2 SBT 框架设计




### 2.3 技术难点

### 2.3.1 SBT 代码发现

- 跳转指令发现：SPC - TPC


### 2.3.2 DBT 运行时开销

- 开销分类：剖析（Profile）、翻译（Translate）。
- Profile：
  - 采样（Sample）：程序中断、处理、恢复开销；
  - 插桩（Instrument）：，插桩开销和收集开销。
- Translate：译码开销。


### 2.3.3 优化代码质量

- 块内优化：常量传播、复写传播、循环不变式外提、冗余分支消除、常量折叠、代码下沉、强度削弱、死代码消除等传统编译器优化，这部分优化的共同特点是无需程序的高层语义信息，能在代码序列的一次遍历中完成代价很小。

- 块间优化：代码重排序、超级块生成、函数内联等，这类优化能够显著减少分支和跳转指令，同时也提高了代码的局部性，能给二进制翻译系统带来极大的性能提升。

- 寄存器分配：分析热代码块找出不活跃寄存器、溢出到内存、超级块寄存器重新分配。


### 2.3.4 提高代码缓存管理效率

1. 动态二进制翻译系统中保存翻译后代码块的一块软件实现的缓冲区，与传统的硬件指令cache相比，它被缓存的代码块没有固定大小;由于代码块间被跳转链接到一起，因此代码块间存在位置的相互依赖；
2. I/D 一致性问题维护；
3. 尽量降低代码缓存在硬件 I-cache 上的失效（提升局部性）；
4. 提升源PC到目标PC的双向映射速度；
5. 替换策略：命中率/替换算法复杂度/替换后代码的重链接开销。


### 2.3.5 体系结构差异

1. 寄存器类型数量差异；
2. 数据表示差异：大小端、舍入模式、NaN；
3. I/O 地址映射差异：内存单独/统一编址；
4. 特权指令翻译：


### 2.3.6 操作系统差异

- 应用级二进制翻译需要转换系统调用；
- 源OS与目标OS相同：ABI不同；
- 源OS与目标OS不同：复杂；

