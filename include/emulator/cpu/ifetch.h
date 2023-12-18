/**
 * @brief CPU 取指令头文件
 * @file include/emulator/cpu/ifetch.h
 * @author lancerstadium
 * @date 2023-10-28
*/

#ifndef _HYBITOR_CPU_IFETCH_H_
#define _HYBITOR_CPU_IFETCH_H_

#include "emulator/softmmu/softmmu.h"

/// @brief 取指令
/// @param pc 程序计数器
/// @param len 指令长度
/// @return 指令值
static inline uint32_t inst_fetch(vaddr_t *pc, int len) {
    uint32_t inst = vaddr_ifetch(*pc, len);
    (*pc) += len;
    return inst;
}

#endif  // _HYBITOR_CPU_IFETCH_H_