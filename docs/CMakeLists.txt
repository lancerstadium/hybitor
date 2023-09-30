
# 指定 CMake 的最低版本要求
cmake_minimum_required(VERSION 3.10)

# 设置项目名称
project(hybitor)

# 指定 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

find_package(LLVM REQUIRED CONFIG)

# 添加可执行文件并指定源文件
add_executable(hybitor 
    src/main.cpp
)

# 添加包含目录，用于包含头文件
include_directories(
    include
)


# 添加链接库搜索路径
link_directories(
    ${CMAKE_SOURCE_DIR}/lib
)

# 寻找 LIEF 静态库
# find_package(LIEF REQUIRED COMPONENTS STATIC)

# 查找并链接外部库
find_library(capstone
    NAMES capstone
    PATHS ${CMAKE_SOURCE_DIR}/lib
)

find_library(LIEF
    NAMES LIEF
    PATHS ${CMAKE_SOURCE_DIR}/lib
)


# 添加链接的库文件
target_link_libraries(hybitor PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/libcapstone-darwin-arm64.a
    ${CMAKE_SOURCE_DIR}/lib/libLIEF-darwin-arm64.a
    LLVM
)

# 设置编译选项
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
else()
    add_compile_options(-O0 -g)
endif()
