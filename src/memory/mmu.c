/**
 * @brief 内存管理操作：MMU, ...
 * @file src/memory/memory.c
 * @author lancerstadium
 * @date 2023-10-15
*/

#include "common.h"
#include "memory/mmu.h"

// ============================================================================ //
// mem 静态变量
// ============================================================================ //

static uint8_t pmem[CONFIG_MSIZE] PG_ALIGN = {};


// ============================================================================ //
// paddr API 实现：物理地址操作--> 声明：include/memory/mmu.h
// ============================================================================ //

uint8_t* guest_to_host(paddr_t paddr) { 
    return pmem + paddr - CONFIG_MBASE; 
}

paddr_t host_to_guest(uint8_t *haddr) { 
    return haddr - pmem + CONFIG_MBASE; 
}

word_t paddr_read(paddr_t addr, int len) {
  if (likely(in_pmem(addr))) return pmem_read(addr, len);
  out_of_bound(addr);
  return 0;
}

void paddr_write(paddr_t addr, int len, word_t data) {
  if (likely(in_pmem(addr))) { pmem_write(addr, len, data); return; }
  out_of_bound(addr);
}

// ============================================================================ //
// vaddr API 实现：物理地址操作--> 声明：include/memory/mmu.h
// ============================================================================ //

word_t vaddr_ifetch(vaddr_t addr, int len) {
  return paddr_read(addr, len);
}

word_t vaddr_read(vaddr_t addr, int len) {
  return paddr_read(addr, len);
}

void vaddr_write(vaddr_t addr, int len, word_t data) {
  paddr_write(addr, len, data);
}


// ============================================================================ //
// mem API 实现：外部控制内存接口 --> 声明：include/memory/mmu.h
// ============================================================================ //

void init_mem() {
    IFDEF(CONFIG_MEM_RANDOM, memset(pmem, rand(), CONFIG_MSIZE));
    Logg("Init mem: physical memory area [" FMT_PADDR ", " FMT_PADDR "]", PMEM_LEFT, PMEM_RIGHT);
}