/**
 * @brief 日志相关操作
 * @file src/utils/log.c
 * @author lancerstadium
 * @date 2023-10-14
*/


#include "utils.h"


// ============================================================================ //
// log 变量
// ============================================================================ //

FILE *log_fp = NULL;    // 文件指针

// ============================================================================ //
// log API 实现 --> 定义 include/utils.h
// ============================================================================ //

/// @brief 外部日志是否开启
/// @return 布尔值
bool output_log_enable() {
    return (log_fp != stdout && log_fp != NULL);
}

void init_log(const char *log_file) {
    log_fp = stdout;
    if (log_file != NULL) {
        FILE *fp = fopen(log_file, "w");
        Assertf(fp, "Can not open '%s'", log_file);
        log_fp = fp;
    }
    Logg("Log is written to %s", log_file ? log_file : "stdout");
}

