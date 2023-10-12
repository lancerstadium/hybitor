# 项目配置
project(
    'capstone2llvmir', 'cpp',
    version: '1.0.0',
    meson_version: '>=0.52',
)

# 获取 C++ 编译器
cpp = meson.get_compiler('cpp')

# -------- 获取主机信息 -------- #
# 获取主机体系结构
host_arch = host_machine.cpu_family()
# 获取构建机器的操作系统类型
os_type = host_machine.system()

# 配置capstone库
capstone = cpp.find_library(
    'capstone', 
    static: true, required: true, 
    dirs : join_paths(meson.source_root(), '../../', 'lib', host_arch + '-' + os_type)
)


# 配置LLVM库
# 设置LLVM版本
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

src_file = [
    './capstone2llvmir_impl.cpp', 
    './capstone2llvmir.cpp', 
    './exceptions.cpp', 
    './llvmir_utils.cpp', 
    './arm/arm_init.cpp', 
    './arm/arm.cpp', 
    './arm64/arm64_init.cpp',
    './arm64/arm64.cpp',
    './mips/mips_init.cpp',
    './mips/mips.cpp',
    './powerpc/powerpc_init.cpp',
    './powerpc/powerpc.cpp',
    './x86/x86_init.cpp',
    './x86/x86.cpp',
]

inc_dir = ['.', './arm/', './arm64/', './mips/', './powerpc/', './x86/', '../capstone/']

# 构建静态库 libcapstone2llvmir.a
libcapstone2llvmir = static_library('capstone2llvmir', src_file)
capstone2llvmir = declare_dependency(
    link_with: libcapstone2llvmir, 
    include_directories: include_directories(inc_dir),
    dependencies: [capstone, LLVM],     # 依赖项
)


