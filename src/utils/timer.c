/**
 * @brief 时间相关操作
 * @file src/utils/timer.c
 * @author lancerstadium
 * @date 2023-10-14
*/


#include "utils.h"

// ============================================================================ //
// timer 静态变量
// ============================================================================ //

static time_t current_time;

// ============================================================================ //
// timer API 实现 --> 定义 include/utils.h
// ============================================================================ //

void print_current_time() {
    time(&current_time);
    printf("Current time: %s", ctime(&current_time));
}

void init_rand() {
    time(&current_time);
    srand((unsigned int)current_time);
}