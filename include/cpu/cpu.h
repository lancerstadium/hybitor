/**
 * @brief CPU头文件
 * @file include/cpu/cpu.h
 * @author lancerstadium
 * @date 2023-10-18
*/

#ifndef _HYBITOR_CPU_CPU_H_
#define _HYBITOR_CPU_CPU_H_

#include "common.h"




// ============================================================================ //
// cpu-exec API 定义：CPU执行接口 --> 实现：src/cpu/cpu-exec.c
// ============================================================================ //

/// @brief cpu退出：处理退出、统计信息打印
void cpu_quit();

/// @brief 模拟CPU执行
/// @param n 执行指令次数
void cpu_exec(uint64_t n);


#endif  // _HYBITOR_CPU_CPU_H