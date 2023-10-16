/**
 * @brief 通用头文件
 * @file include/common.h
 * @author lancerstadium
 * @date 2023-10-13
*/

#ifndef _HYBITOR_COMMON_H_
#define _HYBITOR_COMMON_H_


#include "utils.h"  // 工具头文件


// ============================================================================ //
// 配置文件 宏定义：.config
// ============================================================================ //

#define CONFIG_ISA64 1              // 开启 64 位 ISA
#define CONFIG_RT_CHECK 1           // 开启 RT 检查

// ============================================================================ //
// 类型 宏定义
// ============================================================================ //

// -------- 64 位内存配置宏定义 --------
#if CONFIG_MBASE + CONFIG_MSIZE > 0x100000000ul
#define PMEM64 1    // 64 位内存
#endif

// -------- 根据配置文件决定是否使用 64 位字长 --------
typedef MUXDEF(CONFIG_ISA64, uint64_t, uint32_t) word_t;    // 字长
typedef MUXDEF(CONFIG_ISA64, int64_t, int32_t)  sword_t;    // 符号字长
// -------- 字长格式化输出属性 --------
#define FMT_WORD MUXDEF(CONFIG_ISA64, "0x%016" PRIx64, "0x%08" PRIx32)

typedef word_t vaddr_t;                                      // 虚拟地址
typedef MUXDEF(PMEM64, uint64_t, uint32_t) paddr_t;         // 物理地址
#define FMT_PADDR MUXDEF(PMEM64, "0x%016" PRIx64, "0x%08" PRIx32)
typedef uint16_t ioaddr_t;

// ============================================================================ //
// monitor API 定义 --> 实现 src/monitor/monitor.c
// ============================================================================ //

void init_monitor(int, char *[]);

// ============================================================================ //
// server API 定义 --> 实现 src/server/server.c
// ============================================================================ //

void start_server();

#endif // _HYBITOR_COMMON_H_