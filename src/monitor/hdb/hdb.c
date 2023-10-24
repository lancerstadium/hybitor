/**
 * @brief hybitor debugger 调试器
 * @file src/monitor/hdb/hdb.c
 * @author lancerstadium
 * @date 2023-10-14
*/

#include <readline/readline.h>
#include <readline/history.h>
#include "cpu/cpu.h"
#include "isa.h"
#include "hdb.h"
#include "loader.h"

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
static int cmd_expr(char *);
static int cmd_info(char *);
static int cmd_state(char *);
static int cmd_load(char *);
static int cmd_file(char *);
static int cmd_c(char *);
static int cmd_si(char *);
static int cmd_q(char *);
/// TODO: 实现其他命令

/// @brief 命令列表
static struct {
    const char *name;        // 命令名
    const char *description; // 命令描述
    int (*handler)(char *);  // 命令处理函数
} cmd_table[] = { 
    {"help",  "Display information about all supported commands", cmd_help},
    {"time",  "Print the current time", cmd_time},
    {"expr",  "Print regex rules", cmd_expr},
    {"info",  "Subcommand [r] for reg info, [w] for watchpoint", cmd_info },
    {"state", "Print hybitor statement", cmd_state},
    {"load",  "Reset load img [File]", cmd_load},
    {"file",  "Subcommand [h], [s], [m], [p]", cmd_file},
    {"c",     "Continue the execution of the program", cmd_c},
    {"si",    "Execute [N] step", cmd_si },
    {"q",     "Exit hbd", cmd_q},
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

static int cmd_expr(char *args) {
    print_regex_rules();
    return SUCCESS_RETURN;
}

static int cmd_info(char *args) {
    char *sencond_word = strtok(NULL," ");
    if (sencond_word == NULL){
		Warning("Enter [r]: reg info, [w]: watchpoint info");
		return SUCCESS_RETURN;	
	}
    if (strcmp(sencond_word, "r") == 0) {
        print_isa_reg_info();
    } else if (strcmp(sencond_word, "w") == 0) {
        print_watchpoint_info();
    } else {
        Warningf("Unknown command '%s', enter `r`: reg, `w`: watchpoint", sencond_word);
    }
    return SUCCESS_RETURN;
}

static int cmd_state(char *args) {
    print_hybitor_state();
    return SUCCESS_RETURN;
}

static int cmd_load(char *args) {
    char *sencond_word = strtok(NULL," ");
    if (sencond_word == NULL){
		Warning("Enter a valid [File] path");
		return SUCCESS_RETURN;	
	}
    if(!change_load_img(sencond_word)) {
        return SUCCESS_RETURN;
    }
    load_img_file(img_file);
    return SUCCESS_RETURN;
}

static int cmd_file(char *args) {
    char *sencond_word = strtok(NULL," ");
    if (sencond_word == NULL){
		Warning("Enter valid subcommand [h], [s], [m], [p]");
		return SUCCESS_RETURN;	
	}
    switch (sencond_word[0])
    {
    case 'h':display_img_header_info(); break;
    case 's':display_img_section_info(); break;
    case 'm':display_img_symbol_info(); break;
    case 'p':display_img_program_info(); break;
    default: Warningf("Unknown command '%s', enter `h`: header, `s`: section, `m`: symbol, `p`: program", sencond_word); break;
    }
    return SUCCESS_RETURN;
}


static int cmd_c(char *args) {
    cpu_exec(-1);
    return SUCCESS_RETURN;
}

static int cmd_si(char *args) {
    char *sencond_word = strtok(NULL," ");
    uint64_t step = 0;
	if (sencond_word == NULL){
		cpu_exec(1);
		return SUCCESS_RETURN;	
	}
    sscanf(sencond_word, "%llu", &step);
    if (step <= (uint64_t)0 || 0 > (int)step) { /// TODO: 所以为啥要用u64呢?，判断真麻烦
        Warningf("Enter a valid step(>0): %s", args);
    } else {
        printf("Execute step: %llu\n", step);
        cpu_exec(step);
    }
    return SUCCESS_RETURN;
}

/// @brief 退出程序
/// @param args 参数
/// @return 
static int cmd_q(char *args) {
    cpu_quit();
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

