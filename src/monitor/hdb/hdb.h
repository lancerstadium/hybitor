/**
 * @brief hybitor debugger 调试器定义
 * @file src/monitor/hdb/hdb.h
 * @author lancerstadium
 * @date 2023-10-14
*/

#ifndef _HYBITOR_HDB_H_
#define _HYBITOR_HDB_H_


// ============================================================================ //
// hdb API 定义 --> 实现 src/monitor/hdb/hdb.c
// ============================================================================ //

/// @brief 设置 hdb 为批处理模式
void hdb_set_batch_mode();

/// @brief 初始化 hybitor debugger
void init_hdb();

/// @brief hdb 执行主循环
void hdb_main_loop();

#endif // _HYBITOR_HDB_H_