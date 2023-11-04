/**
 * @brief 内存管理操作：MMU, ...
 * @file src/memory/memory.c
 * @author lancerstadium
 * @date 2023-10-15
*/

#include "common.h"
#include "memory/mmu.h"

// ============================================================================ //
// mem 静态变量 && 函数
// ============================================================================ //

static uint8_t pmem[CONFIG_MSIZE] PG_ALIGN = {};


/// @brief 判断物理地址是否在内存范围内
/// @param addr 物理地址
/// @return 是否在内存范围内
static inline bool in_pmem(paddr_t addr) {
  return addr - CONFIG_MBASE < CONFIG_MSIZE;
}


/// @brief 访问地址出界
/// @param addr 访问地址
static void out_of_bound(paddr_t addr) {
  Fatalf("address = " FMT_PADDR " is out of bound of pmem [" FMT_PADDR ", " FMT_PADDR "] at pc = " FMT_WORD,
      addr, PMEM_LEFT, PMEM_RIGHT, cpu.pc);
}

/// @brief 在pmem中读取数据
/// @param addr 读取地址
/// @param len 长度
/// @return 数据
static word_t pmem_read(paddr_t addr, int len) {
  word_t ret = host_read(guest_to_host(addr), len);
  return ret;
}

/// @brief 在pmem中写入数据
/// @param addr 写入地址
/// @param len 长度
/// @param data 数据
static void pmem_write(paddr_t addr, int len, word_t data) {
  host_write(guest_to_host(addr), len, data);
}

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