/**
 * @brief 控制器操作
 * @file src/controller/controller.c
 * @author lancerstadium
 * @date 2023-10-17
*/

#include "hdb.h"


// ============================================================================ //
// welcome 欢迎信息设置
// ============================================================================ //

/// @brief 打印欢迎信息
static void print_welcome() {
    printf("Welcome to %s%s!\n", ANSI_FMT("hybitor-", ANSI_FG_BLUE), ANSI_FMT(str(CONFIG_GUEST_ARCH), ANSI_FG_BLUE));
    printf("For help, type \"help\"\n");
}


// ============================================================================ //
// controller API 实现 --> 声明 include/common.h
// ============================================================================ //

/// @brief 初始化控制器：加载监视器、内存、镜像文件、初始化线程池、开启服务器
void init_controller_main(int argc, char *argv[]) {
    // 1. 初始化监视器
    init_monitor(argc, argv);
    // 2. 初始化服务器资源
    init_server();
    // 3. 打印欢迎信息
    print_welcome();
}

/// @brief 启动主控制器：执行hdb主循环
void start_controller_main() {
    // 1. 启动服务器
    start_server();
    // 2. 执行hdb主循环
    hdb_main_loop();
}