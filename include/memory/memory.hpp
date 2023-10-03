/**
 * \file include/memory/memory.h
 * \brief 模拟memory：寄存器、Cache、内存
 */


#ifndef MEMORY_MEMORY_H
#define MEMORY_MEMORY_H

#include <unistd.h>

#include "tools/types.hpp"
#include "core/loader.hpp"

// ============================================================================== //
// 寄存器 register
// ============================================================================== //

/// @brief 寄存器对象
class Reg
{
private:

public:
    /// @brief 通用寄存器
    enum gp_reg_type_t {
        zero, ra, sp, gp, tp,
        t0, t1, t2,
        s0, s1,
        a0, a1, a2, a3, a4, a5, a6, a7,
        s2, s3, s4, s5, s6, s7, s8, s9, s10, s11,
        t3, t4, t5, t6,
        num_gp_regs,
    };

    /// @brief 浮点寄存器
    enum fp_reg_type_t {
        ft0, ft1, ft2, ft3, ft4, ft5, ft6, ft7,
        fs0, fs1,
        fa0, fa1, fa2, fa3, fa4, fa5, fa6, fa7,
        fs2, fs3, fs4, fs5, fs6, fs7, fs8, fs9, fs10, fs11,
        ft8, ft9, ft10, ft11,
        num_fp_regs,
    };

    /// @brief 浮点寄存器类别
    typedef union {
        u64 v;  // 全64位 unsigned (default)
        u32 w;  // 低32位 unsigned
        f64 d;  // 全64位 double
        f32 f;  // 低32位 float
    } fp_reg_t;

    Reg() {}
    ~Reg() {}
};



// ============================================================================== //
// 高速缓存 cache
// ============================================================================== //

/// @brief 高速缓存类
class Cache
{
private:

    static const size_t max_cache_entry_size = 64 * 1024;   // 代码块最大存储个数
    static const size_t max_cache_size = 64 * 1024 * 1024;  // 高速缓存大小：64MB

    /// @brief 高速缓存表项
    typedef struct {
        u64 pc;         // 指令计数器  key
        u64 hot;        // 热度值     flag
        u64 offset;     // 偏移量     value
    } cache_item_t;

public:

    u8 *jitcode;    // 可执行内存指针
    u64 offset;     // JIT code 使用地址：不回收
    cache_item_t table[max_cache_entry_size];   // 高速缓存表：哈希表


    Cache() {}
    ~Cache() {}
};


// ============================================================================== //
// 内存 Memory
// ============================================================================== //

/// @brief 内存映射类
class MMU
{
private:
    
public:

    u64 entry;          // 入口地址
    u64 host_alloc;     // 程序内存分割值：最大segament
    u64 alloc;          // 申请内存地址
    u64 base;           // 基址

    MMU() {}
    ~MMU() {}

    void MMU_load_segment(loader ld)
    {
        int page_size = getpagesize();  
        const LIEF::ELF::Header* header = (LIEF::ELF::Header *) &ld.binary->header();
        u64 offset = header->program_headers_offset();

        
    }

};





#endif // MEMORY_MEMORY_H