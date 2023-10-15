/**
 * @brief 监视器操作
 * @file src/monitor/monitor.c
 * @author lancerstadium
 * @date 2023-10-13
*/

#include <getopt.h>     // 参数解析库
#include "mmu.h"
#include "hdb.h"

// ============================================================================ //
// monitor 静态变量
// ============================================================================ //

char *log_file = NULL;   // 日志文件名


// ============================================================================ //
// welcome 欢迎信息设置
// ============================================================================ //

/// @brief 打印欢迎信息
void print_welcome() {
    printf("Welcome to %s!\n", ANSI_FMT("Hybitor", ANSI_FG_BLUE));
    printf("For help, type \"help\"\n");
}


// ============================================================================ //
// args option 实现 ==> 改变三个位置来添加新命令
// ============================================================================ //

/// @brief 打印帮助信息
/// @param argc 参数个数
/// @param argv 参数值
void print_usage_help(int argc, char *argv[]) {
    printf("Usage: %s [OPTION...]\n", argv[0]);
    printf("\t-d, --debug         Enable debug mode\n");
    printf("\t-h, --help          Print help info\n");
    printf("\t-t, --test          Print hello world!\n");
    printf("\t-l, --log=FILE      Output log to FILE\n");
    /// TODO: 打印更多的帮助信息
    printf("\n");
}

/// @brief 解析命令行参数
/// @param argc 参数个数
/// @param argv 参数值
/// @return 错误信息：-1 表示失败，0 表示成功
static int parse_args(int argc, char *argv[]) {
    
    // 参数选项功能列表
    const struct option arg_table[] = {
        {"debug", no_argument      , NULL, 'd'},
        {"help" , no_argument      , NULL, 'h'},
        {"test" , no_argument      , NULL, 't'},
        {"log"  , required_argument, NULL, 'l'},
        /// TODO: 添加更多的参数选项
    };
    int o;  // 接收参数选项
    while ((o = getopt_long(argc, argv, "-dhl:t", arg_table, NULL)) != -1)
    {
        switch (o)
        {   
            /// TODO: 添加处理参数选项
            case 'd':
                hdb_set_debug_mode(); break;
            case 'l':
                log_file = optarg; 
                Assertf((log_file != NULL), "log_file gets NULL : %s", log_file);
                break;
            case 't':
                printf("hello world!\n"); break;
            case -1 :
                Error("input no option"); 
                return FAILURE_RETURN;
            default:
                print_usage_help(argc, argv);
                exit(0);
        }
    } 
    return SUCCESS_RETURN;
}


// ============================================================================ //
// monitor API 实现 --> 定义 include/common.h
// ============================================================================ //

/// @brief 初始化监视器
/// @param argc 参数个数
/// @param argv 参数值
void init_monitor(int argc, char *argv[]) {
    // 1. 解析命令行参数
    parse_args(argc, argv);

    // 2. 设置随机数种子
    init_rand();

    // 3. 初始化日志
    init_log(log_file);

    // 4. 初始化内存
    init_mem();

    // 5. 初始化 hybitor debugger：不管是不是 debug mode 都要初始化
    init_hdb();

    // 6. 打印欢迎信息
    print_welcome();
}




