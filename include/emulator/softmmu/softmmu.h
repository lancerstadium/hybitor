/**
 * @brief MMU内存管理头文件：host, physics address, virtual address
 * @file include/emulator/softmmu/softmmu.h
 * @author lancerstadium
 * @date 2023-10-15
*/

#ifndef _HYBITOR_MEMORY_MMU_H_
#define _HYBITOR_MEMORY_MMU_H_

#include "common.h"

// ============================================================================ //
// memory 宏定义
// ============================================================================ //

#define ROUNDUP(a, sz)   ((((uintptr_t)a) + (sz) - 1) & ~((sz) - 1))
#define ROUNDDOWN(a, sz) ((((uintptr_t)a)) & ~((sz) - 1))

#define PG_ALIGN __attribute((aligned(4096)))

#define PMEM_LEFT  ((paddr_t)CONFIG_MBASE)
#define PMEM_RIGHT ((paddr_t)CONFIG_MBASE + CONFIG_MSIZE - 1)
#define RESET_VECTOR (PMEM_LEFT + CONFIG_PC_RESET_OFFSET)


// ============================================================================ //
// host API：内存读写
// ============================================================================ //

/// @brief 内存读取
/// @param addr 读取地址
/// @param len 读取长度
/// @return 读取到的数据
static inline word_t host_read(void *addr, int len) {
    switch (len) {
    case 1: return *(uint8_t *)addr;
    case 2: return *(uint16_t *)addr;
    case 4: return *(uint32_t *)addr;
    IFDEF(CONFIG_ISA64, case 8 : return *(uint64_t *)addr);
    default: MUXDEF(CONFIG_RT_CHECK, assert(0), return 0);
    }
}

/// @brief 内存写入
/// @param addr 写入地址
/// @param len 数据长度
/// @param data 写入的数据
static inline void host_write(void *addr, int len, word_t data) {
    switch (len) {
    case 1: *(uint8_t *)addr = data; return;
    case 2: *(uint16_t *)addr = data; return;
    case 4: *(uint32_t *)addr = data; return;
    IFDEF(CONFIG_ISA64, case 8 : *(uint64_t *)addr = data; return);
    IFDEF(CONFIG_RT_CHECK, default : assert(0)); 
    }
}


// ============================================================================ //
// paddr API：虚实地址转换
// ============================================================================ //

#define PMEM_LEFT  ((paddr_t)CONFIG_MBASE)
#define PMEM_RIGHT ((paddr_t)CONFIG_MBASE + CONFIG_MSIZE - 1)
#define RESET_VECTOR (PMEM_LEFT + CONFIG_PC_RESET_OFFSET)

/// @brief 将 Guest程序中的 `Guest物理地址` 转换为 Hybitor 中的 `Host虚拟地址`
/// @param paddr 物理地址
/// @return 虚拟地址
uint8_t* guest_to_host(paddr_t paddr);

/// @brief 将 Hybitor中的 `Host虚拟地址` 转换为 Guest程序中的 `Guest物理地址`
/// @param haddr 虚拟地址
/// @return 物理地址
paddr_t host_to_guest(uint8_t *haddr);

/// @brief 从物理地址读取数据
/// @param addr 物理地址
/// @param len 数据长度
/// @return 读取到的数据
word_t paddr_read(paddr_t addr, int len);

/// @brief 向物理地址写入数据
/// @param addr 物理地址
/// @param len 数据长度
/// @param data 写入的数据
void paddr_write(paddr_t addr, int len, word_t data);


// ============================================================================ //
// vaddr API 定义：虚拟地址操作 --> 实现：
// ============================================================================ //

#define PAGE_SHIFT        12
#define PAGE_SIZE         (1ul << PAGE_SHIFT)
#define PAGE_MASK         (PAGE_SIZE - 1)

/// @brief 虚拟地址取指令
/// @param addr 虚拟地址
/// @param len 长度
/// @return 指令
word_t vaddr_ifetch(vaddr_t addr, int len);

/// @brief 虚拟地址读取数据
/// @param addr 虚拟地址
/// @param len 长度
/// @return 数据
word_t vaddr_read(vaddr_t addr, int len);

/// @brief 虚拟地址写入数据
/// @param addr 虚拟地址
/// @param len 长度
/// @param data 数据
void vaddr_write(vaddr_t addr, int len, word_t data);


// ============================================================================ //
// mem API 定义：外部控制内存接口 --> 实现：src/memory/mmu.c
// ============================================================================ //

/// @brief 初始化内存
void init_mem();

#endif // _HYBITOR_MEMORY_MMU_H_
