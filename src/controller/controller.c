/**
 * @brief 控制器操作
 * @file src/controller/controller.c
 * @author lancerstadium
 * @date 2023-10-17
*/

#include "hdb.h"
#include "mmu.h"

// ============================================================================ //
// welcome 欢迎信息设置
// ============================================================================ //

/// @brief 打印欢迎信息
static void print_welcome() {
    printf("Welcome to %s!\n", ANSI_FMT("Hybitor", ANSI_FG_BLUE));
    printf("For help, type \"help\"\n");
}


// ============================================================================ //
// controller API 实现 --> 定义 include/common.h
// ============================================================================ //

/// @brief 初始化控制器：加载镜像文件、初始化线程池
void init_controller() {
    // 1. 初始化内存
    init_mem();
    TODO("start_controller: load img file");
    TODO("start_controller: threads");
    // 4. 打印欢迎信息
    print_welcome();
}

/// @brief 启动主控制器：执行hdb主循环
void start_controller_main() {
    start_server();
    hdb_main_loop();
}