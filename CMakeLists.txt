
# 指定 CMake 的最低版本要求
cmake_minimum_required(VERSION 3.10)

# 设置项目名称
project(hybitor)

# 指定 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# 添加可执行文件并指定源文件
add_executable(hybitor 
    src/main.cpp
)

# 添加包含目录，用于包含头文件
include_directories(include)

# 添加头文件搜索路径
target_include_directories(hybitor
    PRIVATE include   # 私有头文件目录
)

# 添加链接库搜索路径
link_directories(
    ${CMAKE_SOURCE_DIR}/lib
)

# 查找并链接外部库
find_library(capstone
    NAMES capstone
    PATHS ${CMAKE_SOURCE_DIR}/lib
)

# 添加链接的库文件
target_link_libraries(hybitor PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/libcapstone-aarch64.a
)

# 设置编译选项
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
else()
    add_compile_options(-O0 -g)
endif()
