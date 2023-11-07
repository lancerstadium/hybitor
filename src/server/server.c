/**
 * @brief 服务端操作
 * @file src/server/server.c
 * @author lancerstadium
 * @date 2023-10-14
*/

#include "common.h"


/// @brief 初始化服务器
void init_server() {
#ifndef CONFIG_ISA_loongarch32r
    IFDEF(CONFIG_ITRACE, init_disasm(
        MUXDEF(CONFIG_ISA_x86,     "i686",
        MUXDEF(CONFIG_ISA_mips32,  "mipsel",
        MUXDEF(CONFIG_ISA_riscv,
        MUXDEF(CONFIG_RV64,      "riscv64",
                                "riscv32"),
                                "bad"))) "-pc-linux-gnu"
    ));
#endif
    init_isa();
    // 初始化线程池
    TODO("start_controller: muti threads");
}

/// @brief 启动服务器：翻译、优化
void start_server() {
    TODO("start_server: translate");
    TODO("start_server: optimization");
}