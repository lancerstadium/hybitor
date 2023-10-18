/**
 * @brief 时间相关操作
 * @file src/utils/timer.c
 * @author lancerstadium
 * @date 2023-10-14
*/

#include <sys/time.h>
#include "utils.h"

// ============================================================================ //
// timer 静态变量
// ============================================================================ //

static time_t current_time;         // 当前时间
static uint64_t current_timeval;    // 当前时间戳
static uint64_t boot_timeval = 0;   // 启动时间戳

// ============================================================================ //
// timer API 实现 --> 定义 include/utils.h
// ============================================================================ //

uint64_t get_internal_timeval() {
    struct timeval now;
    gettimeofday(&now, NULL);
    uint64_t us = now.tv_sec * 1000000 + now.tv_usec;
    return us;
}

uint64_t get_timeval() {
    if (boot_timeval == 0) 
        boot_timeval = get_internal_timeval();
    current_timeval = get_internal_timeval();
    return current_timeval - boot_timeval;
}

void print_current_time() {
    time(&current_time);
    printf("Current time: %s", ctime(&current_time));
}

void init_rand() {
    srand(get_timeval());
    time(&current_time);
    char *time_buffer = ctime(&current_time);
    time_buffer[strlen(time_buffer) - 1] = '\0';
    Logg("Init rand: current time: %s", time_buffer);
}