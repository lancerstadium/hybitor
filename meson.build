# -------- 配置项目信息 -------- #
project('hybitor-effect', ['c', 'cpp'],
    version: '1.0.0',
    default_options: [
        'default_library=static',
        'cpp_std=c++17',
    ],
    meson_version: '>=0.52'
)
# 获取 C++ 编译器
cpp = meson.get_compiler('cpp')

# -------- 获取主机信息 -------- #
# 获取主机体系结构
host_arch = host_machine.cpu_family()
# 获取构建机器的操作系统类型
os_type = host_machine.system()
# 判断是否小端
if host_machine.endian() != 'little'
  error('Cannot compile for non-little-endian machine!')
endif

# -------- 配置链接库文件 -------- #

# 配置 readline 库
readline = cpp.find_library(
    'readline'
)

# 配置 LLVM 库
# 设置 LLVM 版本
llvm_version = ['>=12', '=<16']
# llvm_lib_path = '/usr/lib/llvm-14/lib'  # 库地点 x86_64 for linux
llvm_lib_path = '/opt/homebrew/opt/llvm/lib' # aarch64 for macbook
# 首先寻找llvm动态库
LLVM = cpp.find_library(
    'LLVM', 
    static: false, required: false,
    dirs : llvm_lib_path
)
# 否则寻找llvm静态库
if not LLVM.found()
    LLVM = cpp.find_library(
        'LLVM', 
        static: true,
        dirs : llvm_lib_path
    )
endif


src_files = [
    'src/hybitor.c',
    'src/monitor/monitor.c',
    'src/monitor/hdb/hdb.c',
    'src/server/server.c',
    'src/utils/timer.c',
    'src/utils/log.c',
    'src/utils/state.c',
    'src/memory/mmu.c',
    'src/monitor/hdb/expr.c',
    'src/monitor/hdb/watchpoint.c',
    'src/controller/controller.c',
    'src/controller/loader/loader.c',
    'src/cpu/cpu-exec.c',
    'src/isa/riscv32/reg.c',    # 体系结构相关
]

inc_dirs = [
    'include',
    'src/monitor/hdb/include',
    'src/controller/loader/include',
    'src/isa/riscv32/include'   # 体系结构相关
]

# -------- 配置可执行文件 -------- #
executable('hybitor',
  sources: src_files,                # 源文件列表
  include_directories: inc_dirs,         # 头文件目录
  dependencies: [LLVM, readline],     # 依赖项
)
