/**
 * @brief 控制器操作
 * @file src/controller/controller.c
 * @author lancerstadium
 * @date 2023-10-17
*/

#include "hdb.h"
#include "mmu.h"
#include "loader.h"

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

/// @brief 初始化控制器：加载监视器、内存、镜像文件、初始化线程池、开启服务器
void init_controller_main(int argc, char *argv[]) {
    // 1. 初始化监视器
    init_monitor(argc, argv);
    // 2. 初始化内存
    init_mem();
    // 3. 加载镜像文件：将镜像加载到内存中。这将覆盖内置镜像。
    long img_size = load_img();
    Logg("Init img: load img_size: %ld", img_size);
    // 4. 初始化线程池
    TODO("start_controller: muti threads");
    // 5. 初始化服务器资源
    init_server();
    // 6. 打印欢迎信息
    print_welcome();
}

/// @brief 启动主控制器：执行hdb主循环
void start_controller_main() {
    // 1. 启动服务器
    start_server();
    // 2. 执行hdb主循环
    hdb_main_loop();
}