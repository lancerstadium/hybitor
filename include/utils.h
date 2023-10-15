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
// 通用工具 宏定义
// ============================================================================ //

// -------------- 串联宏 ---------------
#define concat_temp(x, y) x ## y
#define concat(x, y) concat_temp(x, y)
#define concat3(x, y, z) concat(concat(x, y), z)
#define concat4(x, y, z, w) concat3(concat(x, y), z, w)
#define concat5(x, y, z, v, w) concat4(concat(x, y), z, v, w)

// -------------- 测试宏 ---------------
// From: https://stackoverflow.com/questions/26099745/test-if-preprocessor-symbol-is-defined-inside-macro
#define CHOOSE2nd(a, b, ...) b
#define MUX_WITH_COMMA(contain_comma, a, b) CHOOSE2nd(contain_comma a, b)
#define MUX_MACRO_PROPERTY(p, macro, a, b) MUX_WITH_COMMA(concat(p, macro), a, b)
// 定义某些属性的占位符
#define __P_DEF_0  X,
#define __P_DEF_1  X,
#define __P_ONE_1  X,
#define __P_ZERO_0 X,
// 根据BOOLEAN宏的属性定义一些选择函数
#define MUXDEF(macro, X, Y)  MUX_MACRO_PROPERTY(__P_DEF_, macro, X, Y)
#define MUXNDEF(macro, X, Y) MUX_MACRO_PROPERTY(__P_DEF_, macro, Y, X)
#define MUXONE(macro, X, Y)  MUX_MACRO_PROPERTY(__P_ONE_, macro, X, Y)
#define MUXZERO(macro, X, Y) MUX_MACRO_PROPERTY(__P_ZERO_,macro, X, Y)
// test if a boolean macro is defined 
#define ISDEF(macro) MUXDEF(macro, 1, 0)
// test if a boolean macro is undefined
#define ISNDEF(macro) MUXNDEF(macro, 1, 0)
// test if a boolean macro is defined to 1
#define ISONE(macro) MUXONE(macro, 1, 0)
// test if a boolean macro is defined to 0
#define ISZERO(macro) MUXZERO(macro, 1, 0)
// test if a macro of ANY type is defined
// NOTE1: it ONLY works inside a function, since it calls `strcmp()`
// NOTE2: macros defined to themselves (#define A A) will get wrong results
#define isdef(macro) (strcmp("" #macro, "" str(macro)) != 0)
// 简化条件编译
#define __IGNORE(...)
#define __KEEP(...) __VA_ARGS__
// keep the code if a boolean macro is defined
#define IFDEF(macro, ...) MUXDEF(macro, __KEEP, __IGNORE)(__VA_ARGS__)
// keep the code if a boolean macro is undefined
#define IFNDEF(macro, ...) MUXNDEF(macro, __KEEP, __IGNORE)(__VA_ARGS__)
// keep the code if a boolean macro is defined to 1
#define IFONE(macro, ...) MUXONE(macro, __KEEP, __IGNORE)(__VA_ARGS__)
// keep the code if a boolean macro is defined to 0
#define IFZERO(macro, ...) MUXZERO(macro, __KEEP, __IGNORE)(__VA_ARGS__)




// ============================================================================ //
// 类型工具 宏定义
// ============================================================================ //

// ------------ 数组长度 ------------ 
#define ARRLEN(arr) (int)(sizeof(arr) / sizeof(arr[0]))

// ------------ 字符串长度 ------------
#define STRLEN(CONST_STR) (sizeof(CONST_STR) - 1)

// ------------ BOOL转字符串 ------------
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
    extern bool output_log_enable(); \
    if (output_log_enable()) { \
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
#define Log(fmt, ...) \
    _Log(ANSI_FMT("[%s:%d %s] " fmt, ANSI_FG_BLUE) "\n", \
        __FILE__, __LINE__, __func__, ## __VA_ARGS__)


// ============================================================================ //
// Debug Tools 宏定义：面向调试的信息输出
// ============================================================================ //

// ----------- Fatalf Macro Define：格式化输出错误信息 -----------
#define Fatalf(fmt, ...) (fprintf(stderr, "%s: %s:%d [fatal message]" fmt "\n", ANSI_FMT("Fatal", ANSI_BG_RED ANSI_FG_WHITE), __FILE__, __LINE__, __VA_ARGS__), exit(1))
#define Fatal(msg) Fatalf("%s", msg)        // Fatal Macro Define：输出错误信息
#define Unreachable() Fatal("unreachable")  // Unreachable Macro Define：输出不可达信息
// ----------- Trap Macro Define：格式化输出陷入信息 -----------
#define Trapf(fmt, ...) (fprintf(stderr, "%s: %s:%d [trap message] " fmt "\n", ANSI_FMT("Trap", ANSI_BG_YELLOW ANSI_FG_WHITE), __FILE__, __LINE__, __VA_ARGS__))
#define Trap(msg) Trapf("%s", msg)          // Trap Macro Define：输出待办信息
// ----------- Safe Macro Define：格式化输出安全信息 -----------
#define Safef(fmt, ...) (fprintf(stdout, "%s: %s:%d [safe message] " fmt "\n", ANSI_FMT("Safe", ANSI_BG_GREEN ANSI_FG_WHITE), __FILE__, __LINE__, __VA_ARGS__))
#define Safe(msg) Safef("%s", msg)          // Safe Macro Define：输出安全信息
// ----------- TODO Macro Define：格式化输出待办信息 -----------
#define TODOf(fmt, ...) (fprintf(stderr, "%s: %s:%d [todo message] " fmt "\n", ANSI_FMT("TODO", ANSI_BG_BLUE ANSI_FG_WHITE), __FILE__, __LINE__, __VA_ARGS__))
#define TODO(msg) TODOf("%s", msg)          // TODO Macro Define：输出待办信息
// ----------- Assert Macro Define：格式化输出断言信息 -----------
#define Assertf(cond, fmt, ...) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "%s: %s:%d \n[condition] %s \n[assert message] " fmt "\n",ANSI_FMT("Assert", ANSI_FG_BLACK ANSI_BG_RED), __FILE__, __LINE__, BOOL_TO_STR(cond), __VA_ARGS__); \
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