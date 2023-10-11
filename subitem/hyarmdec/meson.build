# 项目配置
project(
    'hyarmdec', 'c',
    version: '1.0.0',
    meson_version: '>=0.52',
)

# 构建静态库 libhyarmdec.a
libhyarmdec = static_library('hyarmdec', 'decode.c')
hyarmdec = declare_dependency(
    link_with: libhyarmdec, 
    include_directories: include_directories('.'),
)

# 构建可执行文件
executable('arm64dec-test',
  sources: ['arm64dec-test.c', 'decode.c'],                # 源文件列表
  include_directories: ['.'],         # 头文件目录
)
