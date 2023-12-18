/**
 * @brief 服务端操作
 * @file src/server/server.c
 * @author lancerstadium
 * @date 2023-10-14
*/

#include "common.h"
#include "emulator/softmmu/softmmu.h"
#include "loader.h"

/// 获取来宾体系结构字符串
#define GET_GUEST_ARCH_S \
    MUXDEF(CONFIG_ISA_x86,     "i686", \
    MUXDEF(CONFIG_ISA_mips32,  "mipsel", \
    MUXDEF(CONFIG_ISA_riscv, \
        MUXDEF(CONFIG_RV64,    "riscv64", "riscv32"), \
    "bad"))) "-pc-linux-gnu"


/// @brief 初始化服务器
void init_server() {
    // 1. 初始化指令集
    init_isa();
    // 2. 初始化内存
    init_mem();
    // 3. 加载镜像文件：将镜像加载到内存中。这将覆盖内置镜像。
    init_load_img();
    // 4. 初始化反汇编引擎
#ifndef CONFIG_ISA_loongarch32r
    IFDEF(CONFIG_ITRACE, init_disasm(GET_GUEST_ARCH_S));
    IFDEF(CONFIG_ITRACE, Logg("Init disasmble ISA: %s", GET_GUEST_ARCH_S));
#endif
    
    // 5. 初始化线程池
    TODO("start_client: muti threads");
}

/// @brief 启动服务器：翻译、优化
void start_server() {
    TODO("start_server: translate");
    TODO("start_server: optimization");
}