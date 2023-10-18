/**
 * @brief 内存管理操作：MMU, ...
 * @file src/memory/memory.c
 * @author lancerstadium
 * @date 2023-10-15
*/

#include "common.h"
#include "mmu.h"

// ============================================================================ //
// mem 静态变量
// ============================================================================ //

static uint8_t pmem[CONFIG_MSIZE] PG_ALIGN = {};


// ============================================================================ //
// paddr API 实现：物理地址操作--> 定义：include/memory/mmu.h
// ============================================================================ //

uint8_t* guest_to_host(paddr_t paddr) { 
    return pmem + paddr - CONFIG_MBASE; 
}

paddr_t host_to_guest(uint8_t *haddr) { 
    return haddr - pmem + CONFIG_MBASE; 
}

// ============================================================================ //
// mem API 实现：外部控制内存接口 --> 定义：include/memory/mmu.h
// ============================================================================ //

void init_mem() {
    IFDEF(CONFIG_MEM_RANDOM, memset(pmem, rand(), CONFIG_MSIZE));
    Logg("Init mem: physical memory area [" FMT_PADDR ", " FMT_PADDR "]", PMEM_LEFT, PMEM_RIGHT);
}