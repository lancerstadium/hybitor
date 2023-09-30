project('hybitor', 'cpp')

# 获取 C++ 编译器
cpp = meson.get_compiler('cpp')


# 配置库文件
libs = meson.get_compiler('cpp').find_library(
    'LIEF-linux-x86_64', dirs : join_paths(meson.source_root(),'lib')
)

# 配置可执行文件
executable('hybitor',
  sources: ['src/main.cpp'],            # 源文件列表
  include_directories: ['include'],     # 头文件目录
  dependencies: [libs],                 # 依赖项
)
