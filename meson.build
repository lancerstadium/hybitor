# -------- 配置项目信息 -------- #
project('hybitor-effect', ['c', 'cpp'],
    version: '1.0.0',
    default_options: [
        'default_library=static',
        'cpp_std=c++17',
    ],
    meson_version: '>=0.54'
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
    'readline',
)

# 配置 elf 库
libelf = cpp.find_library(
    'elf',
)

# 配置 LLVM 库
# 设置 LLVM 版本
llvm_version = ['>=12', '=<16']
llvm_lib_path = '/usr/lib/llvm-15/lib'  # 库地点 x86_64 for linux
llvm_include_path = [                   # 头地点 x86_64 for linux
    '/usr/include/llvm-15',
    '/usr/include/llvm-c-15',
]
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

# -------- 配置路径文件 -------- #

guest_arch = 'riscv64'
guest_isa_path = 'src/isa/' + guest_arch

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
    guest_isa_path + '/reg.c',     # 体系结构相关
    guest_isa_path + '/init.c',    # 体系结构相关
    guest_isa_path + '/inst.c',    # 体系结构相关
    guest_isa_path + '/logo.c',    # 体系结构相关
    'src/server/interpreter/hostcall.c',
    'src/server/decoder/decode.cc',
]

inc_dirs = [
    llvm_include_path,
    '.',
    'include',
    'src/monitor/hdb/include',
    'src/controller/loader/include',
    'src/isa/riscv32/include',      # 体系结构相关
    guest_isa_path + '/include',      # 体系结构相关
]

# -------- 配置文件 -------- #
conf_data = configuration_data()

## 通用配置
conf_data.set('CONFIG_VERSION', '0.4.1', description: '配置文件版本')
conf_data.set('CONFIG_GUEST_ARCH', guest_arch, description: '来宾体系结构')
conf_data.set('CONFIG_TARGET_ARCH', host_arch, description: '主机体系结构')
conf_data.set('CONFIG_MBASE', '0x80000000', description: '内存基址')
conf_data.set('CONFIG_MSIZE', '0x8000000', description: '内存大小')
conf_data.set('CONFIG_MEM_RANDOM', 1, description: '内存随机初始化')
conf_data.set('CONFIG_PC_RESET_OFFSET', '0x0', description: '取指令偏移')
# conf_data.set('CONFIG_RVE', 1, description: '开启相对虚拟地址')

## ISA配置
if guest_arch == 'riscv64'
    conf_data.set('CONFIG_ISA64', 1, description: '是 64bit ISA')
    conf_data.set('CONFIG_ISA_riscv', 1, description: '是 RISC-V ISA')
    conf_data.set('CONFIG_RV64', 1, description: '是 RISC-V 64bit ISA')
    message('Config guest architecture: \033[1;32m@0@\033[0m'.format(guest_arch))
elif guest_arch == 'aarch64'
    conf_data.set('CONFIG_ISA64', 1, description: '是 64bit ISA')
    conf_data.set('CONFIG_ISA_aarch', 1, description: '是 aarch ISA')
    conf_data.set('CONFIG_ARM64', 1, description: '是 ARM 64bit ISA')
    message('Config guest architecture: \033[1;32m@0@\033[0m'.format(guest_arch))
endif


## 可选配置
conf_data.set('CONFIG_ITRACE', 1, description: '开启指令追踪')
conf_data.set('CONFIG_RT_CHECK', 1, description: '开启实时检查')

configure_file(
    install: true,
    install_dir: './include/config',
    output: 'config.h',
    configuration: conf_data,
)


# -------- 配置可执行文件 -------- #
executable('hybitor',
  sources: src_files,                # 源文件列表
  include_directories: inc_dirs,         # 头文件目录
  dependencies: [LLVM, readline, libelf],     # 依赖项
)
