/**
 * @brief 服务端头文件
 * @file include/server/server.h
 * @author lancerstadium
 * @date 2023-12-18
*/

#ifndef _HYBITOR_SERVER_SERVER_H_
#define _HYBITOR_SERVER_SERVER_H_

#include <config.h> // 配置文件
#include "utils.h"  // 工具头文件
#include "emulator/isa.h"    // 指令集相关 API 头文件


// ============================================================================ //
// server API 定义 --> 实现 src/server/server.c
// ============================================================================ //

void init_server();
void start_server();
void init_disasm(const char *triple);
int get_inst_len(uint64_t pc, uint8_t *code, int nbyte);
void disassemble(char *str, int size, uint64_t pc, uint8_t *code, int nbyte);

#endif // _HYBITOR_SERVER_SERVER_H_