/**
 * @brief hybitor debugger 调试器定义
 * @file src/monitor/hdb/hdb.h
 * @author lancerstadium
 * @date 2023-10-14
*/

#ifndef _HYBITOR_HDB_H_
#define _HYBITOR_HDB_H_

#include "common.h"

// ============================================================================ //
// watchpoint API 定义 --> 实现 src/monitor/hdb/watchpoint.c
// ============================================================================ //

/// @brief 初始化观测点工具
void init_wp_pool();


// ============================================================================ //
// expr API 定义 --> 实现 src/monitor/hdb/expr.c
// ============================================================================ //

/// @brief 初始化表达式解析器
void init_regex();

/// @brief 打印表达式规则
void print_regex_rules();

/// @brief 表达式解析
word_t expr(char *e, bool *success);

// ============================================================================ //
// hdb API 定义 --> 实现 src/monitor/hdb/hdb.c
// ============================================================================ //

/// @brief 设置 hdb 为debug模式
void hdb_set_debug_mode();

/// @brief 初始化 hybitor debugger
void init_hdb();

/// @brief hdb 执行主循环
void hdb_main_loop();

#endif // _HYBITOR_HDB_H_