#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <assert.h>
#include <errno.h>


#define fatalf(fmt, ...) (fprintf(stderr, "fatal: %s:%d " fmt "\n", __FILE__, __LINE__, __VA_ARGS__), exit(1))
/// fatal 宏：输出错误信息
#define fatal(msg) fatalf("%s", msg)
/// todo 宏：输出待办信息
#define todo(msg) (fprintf(stderr, "warning: %s:%d [TODO] %s\n", __FILE__, __LINE__, msg))
/// unreachable 宏：输出不可达信息
#define unreachable() (fatal("unreachable"), __builtin_unreachable())


#endif // DEBUG_H