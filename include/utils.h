/**
 * @brief 工具头文件
 * @file include/utils.h
 * @author lancerstadium
 * @date 2023-10-14
*/

#ifndef _HYBITOR_UTILS_H_
#define _HYBITOR_UTILS_H_

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>




// ============================================================================ //
// 类型 简单宏定义
// ============================================================================ //


#define BOOL_TO_STR(bool_expr) (bool_expr) ? "true" : "false"

// ============================================================================ //
// Log 宏定义
// ============================================================================ //

// ----------- ANSI Color ----------- 
#define ANSI_FG_BLACK   "\33[1;30m" // 前景：黑
#define ANSI_FG_RED     "\33[1;31m" // 前景：红
#define ANSI_FG_GREEN   "\33[1;32m" // 前景：绿
#define ANSI_FG_YELLOW  "\33[1;33m" // 前景：黄
#define ANSI_FG_BLUE    "\33[1;34m" // 前景：蓝
#define ANSI_FG_MAGENTA "\33[1;35m" // 前景：品红
#define ANSI_FG_CYAN    "\33[1;36m" // 前景：青
#define ANSI_FG_WHITE   "\33[1;37m" // 前景：白
#define ANSI_BG_BLACK   "\33[1;40m" // 前景：黑
#define ANSI_BG_RED     "\33[1;41m" // 前景：红
#define ANSI_BG_GREEN   "\33[1;42m" // 前景：绿
#define ANSI_BG_YELLOW  "\33[1;43m" // 前景：黄
#define ANSI_BG_BLUE    "\33[1;44m" // 前景：蓝
#define ANSI_BG_MAGENTA "\33[1;35m" // 背景：品红
#define ANSI_BG_CYAN    "\33[1;46m" // 背景：青
#define ANSI_BG_WHITE   "\33[1;47m" // 背景：白
#define ANSI_NONE       "\33[0m"    // No Color

// ----------- ANSI Fomate ----------- 
#define ANSI_FMT(str, fmt) fmt str ANSI_NONE

#define log_write(...)  \
  do { \
    extern FILE* log_fp; \
    extern bool log_enable(); \
    if (log_enable()) { \
      fprintf(log_fp, __VA_ARGS__); \
      fflush(log_fp); \
    } \
  } while (0) \


#define _Log(...) \
  do { \
    printf(__VA_ARGS__); \
    log_write(__VA_ARGS__); \
  } while (0)

// ----------- Log Macro Define ----------- 
#define Log(format, ...) \
    _Log(ANSI_FMT("[%s:%d %s] " format, ANSI_FG_BLUE) "\n", \
        __FILE__, __LINE__, __func__, ## __VA_ARGS__)


// ============================================================================ //
// Debug Tools 宏定义：面向调试的信息输出
// ============================================================================ //

// ----------- Fatalf Macro Define：格式化输出错误信息 -----------
#define Fatalf(fmt, ...) (fprintf(stderr, "%s: %s:%d [fatal message]" fmt "\n", ANSI_FMT("Fatal", ANSI_FG_WHITE ANSI_BG_RED), __FILE__, __LINE__, __VA_ARGS__), exit(1))
#define Fatal(msg) Fatalf("%s", msg)        // Fatal Macro Define：输出错误信息
#define Unreachable() Fatal("unreachable")  // Unreachable Macro Define：输出不可达信息
// ----------- Trap Macro Define：格式化输出陷入信息 -----------
#define Trapf(fmt, ...) (fprintf(stderr, "%s: %s:%d [trap message] " fmt "\n", ANSI_FMT("Trap", ANSI_FG_WHITE ANSI_BG_YELLOW), __FILE__, __LINE__, __VA_ARGS__))
#define Trap(msg) Trapf("%s", msg)          // Trap Macro Define：输出待办信息
// ----------- Safe Macro Define：格式化输出安全信息 -----------
#define Safef(fmt, ...) (fprintf(stdout, "%s: %s:%d [safe message] " fmt "\n", ANSI_FMT("Safe", ANSI_FG_WHITE ANSI_BG_GREEN), __FILE__, __LINE__, __VA_ARGS__))
#define Safe(msg) Safef("%s", msg)          // Safe Macro Define：输出安全信息
// ----------- TODO Macro Define：格式化输出待办信息 -----------
#define TODOf(fmt, ...) (fprintf(stderr, "%s: %s:%d [todo message] " fmt "\n", ANSI_FMT("TODO", ANSI_FG_WHITE ANSI_BG_BLUE), __FILE__, __LINE__, __VA_ARGS__))
#define TODO(msg) TODOf("%s", msg)          // TODO Macro Define：输出待办信息
// ----------- Assert Macro Define：格式化输出断言信息 -----------
#define Assertf(cond, fmt, ...) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "%s: %s:%d \n[condition] %s \n[assert message] " fmt "\n",ANSI_FMT("Assert", ANSI_FG_WHITE ANSI_BG_RED), __FILE__, __LINE__, BOOL_TO_STR(cond), __VA_ARGS__); \
            abort(); \
        } \
    } while (0)
#define Assert(cond, msg) Assertf(cond, "%s", msg)  // Assert Macro Define：输出断言信息

#define SUCCESS_RETURN 0        // 成功返回
#define FAILURE_RETURN -1       // 失败返回

// ============================================================================ //
// User Info Tools 宏定义：面向用户的信息输出
// ============================================================================ //

// ----------- Error Macro Define：格式化用户错误信息 -----------
#define Errorf(fmt, ...) (fprintf(stderr, "%s: %s:%d [error type] " fmt "\n", ANSI_FMT("Error", ANSI_FG_RED), __FILE__, __LINE__, __VA_ARGS__))
#define Error(msg) Errorf("%s", msg)        // Error Macro Define：输出错误信息
// ----------- Warning Macro Define：格式化用户警告信息 -----------
#define Warningf(fmt, ...) (fprintf(stderr, "%s: %s:%d [warning type] " fmt "\n", ANSI_FMT("Warning", ANSI_FG_YELLOW), __FILE__, __LINE__, __VA_ARGS__))
#define Warning(msg) Warningf("%s", msg)    // Warning Macro Define：输出警告信息
// ----------- Success Macro Define：格式化用户成功信息 -----------
#define Successf(fmt, ...) (fprintf(stdout, "%s: %s:%d [success type] " fmt "\n", ANSI_FMT("Success", ANSI_FG_GREEN), __FILE__, __LINE__, __VA_ARGS__))
#define Success(msg) Successf("%s", msg)    // Success Macro Define：输出成功信息



// ============================================================================ //
// 长度测量 宏定义
// ============================================================================ //

// ------------ 数组长度 ------------ 
#define ARRLEN(arr) (int)(sizeof(arr) / sizeof(arr[0]))

// ------------ 字符串长度 ------------
#define STRLEN(CONST_STR) (sizeof(CONST_STR) - 1)



// ============================================================================ //
// timer API 定义 --> 实现 src/utils/timer.c
// ============================================================================ //

/// @brief 打印当前时间
void print_current_time();

/// @brief 初始化随机数
void init_rand();


// ============================================================================ //
// log API 定义 --> 实现 src/utils/log.c
// ============================================================================ //


/// @brief 初始化日志
void init_log(const char *);


#endif // _HYBITOR_UTILS_H_