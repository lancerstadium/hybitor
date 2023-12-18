/**
 * @brief 客户端头文件
 * @file include/client/client.h
 * @author lancerstadium
 * @date 2023-12-18
*/

#ifndef _HYBITOR_CLIENT_CLIENT_H_
#define _HYBITOR_CLINET_CLIENT_H_

#include <config.h> // 配置文件
#include "utils.h"  // 工具头文件

// ============================================================================ //
// client API 定义 --> 实现 src/client/client.c
// ============================================================================ //

void init_client_main(int, char *[]);
void start_client_main();
void connect_to_server();

// ============================================================================ //
// monitor API 定义 --> 实现 src/monitor/monitor.c
// ============================================================================ //

void init_monitor(int, char *[]);

#endif // _HYBITOR_CLIENT_CLIENT_H_