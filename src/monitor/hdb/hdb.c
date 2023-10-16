/**
 * @brief hybitor debugger 调试器
 * @file src/monitor/hdb/hdb.c
 * @author lancerstadium
 * @date 2023-10-14
*/

#include <readline/readline.h>
#include <readline/history.h>
#include "common.h"
#include "hdb.h"

// ============================================================================ //
// hdb 静态变量
// ============================================================================ //

static int is_debug_mode = false;

// ============================================================================ //
// hdb 命令行读取工具
// ============================================================================ //

/// @brief 读取命令行输入
/// @return 命令行输入字符串
static char *readline_gets() {
    static char *line_read = NULL;
    if (line_read) {
        free(line_read);
        line_read = NULL;
    }
    line_read = readline("(hdb) ");
    if (line_read && *line_read) {
        add_history(line_read);
    }
    return line_read;
}

// ============================================================================ //
// hdb command 命令实现
// ============================================================================ //

static int cmd_help(char *);
static int cmd_time(char *);
static int cmd_c(char *);
static int cmd_q(char *);
/// TODO: 实现其他命令

/// @brief 命令列表
static struct {
    const char *name;        // 命令名
    const char *description; // 命令描述
    int (*handler)(char *);  // 命令处理函数
} cmd_table[] = { 
    {"help", "Display information about all supported commands", cmd_help},
    {"time", "Print the current time", cmd_time},
    {"c", "Continue the execution of the program", cmd_c},
    {"q", "Exit hbd", cmd_q},
    /// TODO: 实现其他命令描述
};

// ------------- 命令列表长度 ------------
#define NR_CMD ARRLEN(cmd_table)

/// @brief 打印帮助信息
/// @param args 参数
/// @return 
static int cmd_help(char *args) {
    // 获取第一个参数
    char *arg = strtok(NULL, " ");
    int i;
    if (arg == NULL) { // 没有参数则循环打印命令名和描述
        for (i = 0; i < NR_CMD; i++) {
            printf("   %-5s - %s\n", cmd_table[i].name, cmd_table[i].description);
        }
    } else {    // 有参数则循环打印命令名和描述
        for (i = 0; i < NR_CMD; i++) {
            if (strcmp(arg, cmd_table[i].name) == 0) {
                printf("   %-5s - %s\n", cmd_table[i].name, cmd_table[i].description);
                return SUCCESS_RETURN;
            }
        }
        printf("Unknown command '%s'\n", arg);
    }
    return SUCCESS_RETURN;
}

static int cmd_time(char *args) {
    print_current_time();
    return SUCCESS_RETURN;
}

static int cmd_c(char *args) {
    TODO("Executing the program!");
    return SUCCESS_RETURN;
}

/// @brief 退出程序
/// @param args 参数
/// @return 
static int cmd_q(char *args) {
    printf("Bye!\n");
    exit(0);
    return SUCCESS_RETURN;    
}


// ============================================================================ //
// hdb API 实现 --> 定义 src/monitor/hdb/hdb.h
// ============================================================================ //

void hdb_set_debug_mode() {
    is_debug_mode = true;
}

void init_hdb() {
    // 1. 初始化表达式解析器
    init_regex();
    // 2. 初始化观测点工具
    init_wp_pool();
}

void hdb_main_loop() {
    // 1. 如果不为debug模式,则执行程序
    if (!is_debug_mode) {
        cmd_c(NULL);
        return;
    }

    // 2. 读取命令行输入，并执行命令
    for(char *str; (str = readline_gets()) != NULL ;) {
        char *str_end = str + strlen(str);

        // 提取第一个参数：用空格分隔
        char *cmd = strtok(str, " ");
        if (cmd == NULL) { continue; }

        // 将剩余字符串转化为新命令行输入，继续解析
        char *args = cmd + strlen(cmd) + 1;
        if(args >= str_end) {
            args = NULL;
        }

        // 3. 执行命令
        int i;
        for (i = 0; i < NR_CMD; i++) {
            if (strcmp(cmd, cmd_table[i].name) == 0) {
                if (cmd_table[i].handler(args) < 0) { return; }
                break;
            }
        }

        // 4. 如果命令不存在，则打印未知信息
        if (i == NR_CMD) { Warningf("Unknown command: %s", cmd); }
    } // hdb main loop for
}

