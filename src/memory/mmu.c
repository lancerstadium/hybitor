/**
 * @brief 内存管理操作：MMU, ...
 * @file src/memory/memory.c
 * @author lancerstadium
 * @date 2023-10-15
*/

#include "common.h"
#include "mmu.h"



static uint8_t pmem[CONFIG_MSIZE] PG_ALIGN = {};


// ============================================================================ //
// mem API 实现：外部控制内存接口 --> 实现：src/memory/mmu.c
// ============================================================================ //

void init_mem() {
    IFDEF(CONFIG_MEM_RANDOM, memset(pmem, rand(), CONFIG_MSIZE));
    Logg("Init mem: physical memory area [" FMT_PADDR ", " FMT_PADDR "]", PMEM_LEFT, PMEM_RIGHT);
}