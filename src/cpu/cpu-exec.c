/**
 * @brief CPU执行函数实现
 * @file src/cpu/cpu-exec.c
 * @author lancerstadium
 * @date 2023-10-18
*/

#include "cpu/cpu.h"

// ============================================================================ //
// cpu-exec 宏定义
// ============================================================================ //

/* The assembly code of instructions executed is only output to the screen
 * when the number of instructions executed is less than this value.
 * This is useful when you use the `si' command.
 * You can modify this value as you want.
 */
#define MAX_INST_TO_PRINT 10


// ============================================================================ //
// cpu-exec 静态变量
// ============================================================================ //

CPU_state cpu = {};
uint64_t g_nr_guest_inst = 0;       // 程序执行指令数
static uint64_t g_timer = 0;        // 程序执行时间
static bool g_print_step = false;   // 是否打印执行指令


// ============================================================================ //
// cpu-exec 静态函数
// ============================================================================ //

/// @brief cpu执行指令
/// @param n 指令数
static void cpu_execute(uint64_t n) {
    if(n == -1){
        TODO("cpu_execute_-1_loop");
        change_hybitor_state(HY_ABORT);
        return;
    }
    for (;n > (uint64_t)0; n --) {
        g_nr_guest_inst++;
        if (hybitor_state.state != HY_RUNNING)
            break;
    }
    TODO("cpu_execute");
}


// ============================================================================ //
// cpu-exec API 实现：CPU执行接口 --> 定义：include/cpu/cpu.h
// ============================================================================ //

void cpu_quit() {
    change_hybitor_state(HY_QUIT);
    Logg("Host time spent = %0.8f us", (double)g_timer);
    Logg("Guest executed instructions = %d", (int)g_nr_guest_inst);
    if(g_timer > 0)
        Logg("Frequency = %0.8f inst/s", (double)g_nr_guest_inst * 1000000 / g_timer);
    else
        Logy("Finish running in less than 1 us : %0.8f us, Can not calculate the simulation frequency.", (double)g_timer);
}

void cpu_exec(uint64_t n) {
    g_print_step = (n < MAX_INST_TO_PRINT);
    // 检查 hybitor 状态
    switch (hybitor_state.state) {
    case HY_END:
        Success("Program execution has ended. To restart the program, exit `hdb` and run again.");
        return;
    case HY_ABORT:
        Warning("Program execution is aborted. To restart the program, exit `hdb` and run again.");
        return;
    default:
        change_hybitor_state(HY_RUNNING);
        break;
    }

    uint64_t timer_start = get_timeval();

    cpu_execute(n);

    uint64_t timer_end = get_timeval();
    g_timer += (timer_end - timer_start);

    // 检查 hybitor 退出CPU循环的状态
    check_hybitor_quit_state();
}