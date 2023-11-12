/**
 * @brief 通用头文件
 * @file include/common.h
 * @author lancerstadium
 * @date 2023-10-13
*/

#ifndef _HYBITOR_COMMON_H_
#define _HYBITOR_COMMON_H_

#include <config.h> // 配置文件
#include "utils.h"  // 工具头文件
#include "isa.h"    // 指令集相关 API 头文件


// ============================================================================ //
// monitor API 定义 --> 实现 src/monitor/monitor.c
// ============================================================================ //

void init_monitor(int, char *[]);

// ============================================================================ //
// controller API 定义 --> 实现 src/controller/controller.c
// ============================================================================ //

void init_controller_main(int, char *[]);
void start_controller_main();

// ============================================================================ //
// server API 定义 --> 实现 src/server/server.c
// ============================================================================ //

void init_server();
void start_server();
void init_disasm(const char *triple);
int get_inst_len(uint64_t pc, uint8_t *code, int nbyte);
void disassemble(char *str, int size, uint64_t pc, uint8_t *code, int nbyte);

#endif // _HYBITOR_COMMON_H_