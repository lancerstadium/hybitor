# Hybitor

## 待办事项（TODO）

| number | module | tools | version | yes or no |
|---|---|---|---|---|
| 1 | clienv | CLI11 | CLI_v2.3.2 | ✅ |
| 2 | binaryfile | libbfd |  |  |
| 3 | disassembler | capstone | capstone_v5.0.0 |  |



## 0 项目说明

### 0.0 项目介绍

- `Hybitor` 是一个静态二进制翻译器（*Static Binary Translator*）：
  - 功能：输入 `Guest` 端 ELF 可执行文件，将其静态翻译为 `LLVM IR`，输出 `Host` 端 ELF 可执行文件；
  - 依赖：`qemu-user-6.0`, `llvm-project-16.0`
  - 目标：模块化、效率、支持多种编译优化选项、支持Profile、多线程；
  - 应用场景：让`Guest`应用程序运行在不同体系架构的`Host`端主机上。


### 0.1 项目构建

1. 依赖准备：

```shell
qemu-arm --version
opt --veriosn
```


2. 构建：

```shell
mkdir build/
cd build/
cmake ..
make -j$(nproc)
make install
```

3. 简单的例子：

```shell
cd build
cat > hello.c <<EOF
#include <stdio.h>

int main(int argc, char *argv[]) {
    printf("Hello, world!\n");
}
EOF

armv7a-hardfloat-linux-uclibceabi-gcc -static hello.c -o hello.arm
./translate hello.arm
# ...
./hello.arm.translated
Hello, world!
```



## 1 项目设计

### 1.1 目录结构

- C++项目目录，帮助组织和管理代码、资源和构建文件：

```
project/
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
│   └── release/       # 发行构建目录
│
├── CMakeLists.txt     # CMake构建系统配置文件（如果使用CMake）
├── README.md          # 项目文档
└── .gitignore         # Git忽略文件列表

```

- 文件及目录说明：
  - `src/` 目录包含项目的源代码文件，通常包括主程序入口和各个模块的源代码。
  - `include/` 目录包含项目的头文件，用于声明类、函数、常量等。这些头文件通常与源文件一一对应。
  - `lib/` 目录可以用于存放第三方库文件，如果你的项目依赖于外部库。
  - `build/` 目录通常用于存放构建生成的文件，例如可执行文件和中间构建文件。这个目录是可选的，你可以根据喜好将构建文件放在其他位置。如果你使用CMake或Make等构建系统，可以在项目根目录下包含相应的构建系统配置文件（例如，CMakeLists.txt 或 Makefile）。
  - `README.md` 文件通常包含项目的简要说明、使用方法、依赖项和其他有用信息。
  - `.gitignore` 文件用于指定哪些文件或目录应该被Git版本控制系统忽略。




export DYLD_LIBRARY_PATH=/opt/homebrew/Cellar/capstone/5.0.1/lib:$DYLD_LIBRARY_PATH

