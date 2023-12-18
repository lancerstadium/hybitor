/**
 * @brief CPU头文件
 * @file include/emulator/cpu/cpu.h
 * @author lancerstadium
 * @date 2023-10-18
*/

#ifndef _HYBITOR_CPU_CPU_H_
#define _HYBITOR_CPU_CPU_H_

#include "common.h"


// ============================================================================ //
// cpu 宏定义
// ============================================================================ //

/// @brief 非法指令 定义 -->实现：src/server/inrterpreter/hostcall.c
/// @param thispc 当前程序计数器
void invalid_inst(vaddr_t thispc);

// -------- 陷入宏 ----------
#define HYTRAP(thispc, code) set_hybitor_state(HY_END, thispc, code)
// -------- 非法宏 ----------
#define HYINVALID(thispc) invalid_inst(thispc)

// ============================================================================ //
// cpu-exec API 定义：CPU执行接口 --> 实现：src/cpu/cpu-exec.c
// ============================================================================ //

/// @brief cpu退出：处理退出、统计信息打印
void cpu_quit();

/// @brief 模拟CPU执行
/// @param n 执行指令次数
void cpu_exec(uint64_t n);


#endif  // _HYBITOR_CPU_CPU_H