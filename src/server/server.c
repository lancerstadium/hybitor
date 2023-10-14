/**
 * @brief 服务端操作
 * @file src/server/server.c
 * @author lancerstadium
 * @date 2023-10-14
*/

#include "hdb.h"

/// @brief 启动服务器
void start_server() {
    hdb_main_loop();
}