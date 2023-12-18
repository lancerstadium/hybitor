/**
 * @brief 控制器操作
 * @file src/client/client.c
 * @author lancerstadium
 * @date 2023-10-17
*/

#include "hdb.h"
#include "loader.h"
#include "emulator/softmmu/softmmu.h"

// ============================================================================ //
// welcome 欢迎信息设置
// ============================================================================ //

/// @brief 打印欢迎信息
static void print_welcome() {
    printf("Welcome to %s%s!\n", ANSI_FMT("hybitor-", ANSI_FG_BLUE), ANSI_FMT(str(CONFIG_GUEST_ARCH), ANSI_FG_BLUE));
    printf("For help, type \"help\"\n");
}


// ============================================================================ //
// client API 实现 --> 声明 include/common.h
// ============================================================================ //

/// @brief 初始化客户端：加载监视器、内存、镜像文件
void init_client_main(int argc, char *argv[]) {
    // 1. 初始化监视器
    init_monitor(argc, argv);
    // 2. 初始化指令集
    init_isa();
    // 3. 初始化内存
    init_mem();
    // 4. 加载镜像文件：将镜像加载到内存中。这将覆盖内置镜像。
    init_load_img();
    // 5. 打印欢迎信息
    print_welcome();
}

void connect_to_server() {
    // 1. 初始化服务器
    init_server();
    // 2. 启动服务器
    start_server();
    TODO("Connect to server");
}

/// @brief 启动客户端：执行hdb主循环
void start_client_main() {
    // 1. 连接到服务器
    connect_to_server();
    // 2. 执行hdb主循环
    hdb_main_loop();
}