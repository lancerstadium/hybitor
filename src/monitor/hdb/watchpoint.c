/**
 * @brief hybitor debugger 的观测点工具
 * @file src/monitor/hdb/watchpoint.c
 * @author lancerstadium
 * @date 2023-10-16
*/

#include "hdb.h"
#include "common.h"


// ============================================================================ //
// watchpoint 静态变量
// ============================================================================ //

/// @brief 观测点数量
#define NR_WP 32

/// @brief 观测点结构体
typedef struct watchpoint {
    int NO;                     // 观测点编号
    struct watchpoint *next;    // 下一个观测点

    /// TODO: 如有必要，添加更多元素

} WP;

/// @brief 观测点池
static WP wp_pool[NR_WP] = {};

/// @brief 观测点头指针，用于插入观测点
static WP *head = NULL, *free_ = NULL;

// ============================================================================ //
// watchpoint API 实现 --> 定义 src/monitor/hdb/hdb.h
// ============================================================================ //

void init_wp_pool() {
    int i;
    for (i = 0; i < NR_WP; i++) {   // 初始化观测点池
        wp_pool[i].NO = i;
        wp_pool[i].next = (i == NR_WP - 1 ? NULL : &wp_pool[i + 1]);
    }
    head = NULL;        // 初始化观测点头指针
    free_ = wp_pool;    // 初始化观测点 free 指针
    Logg("Init watchpoint: pool number: %d", NR_WP);
}


void print_watchpoint_info() {
    TODO("print_watchpoint_info");
}

/// TODO: 实现监视点的功能

