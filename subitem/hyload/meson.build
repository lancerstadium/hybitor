# 项目配置
project(
    'hyload', 'c',
    version: '1.0.0',
    meson_version: '>=0.52',
)

# 构建静态库 libhyarmdec.a
libhyload = static_library('hyload', 'load.c')
hyload = declare_dependency(
    link_with: libhyload, 
    include_directories: include_directories('.'),
)

# 构建可执行文件
executable('elfload-test',
  sources: ['elfload-test.c', 'load.c'],                # 源文件列表
  include_directories: ['.'],         # 头文件目录
)
