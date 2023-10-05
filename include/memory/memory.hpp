/**
 * \file include/memory/memory.h
 * \brief 模拟memory：寄存器、Cache、内存
 */


#ifndef MEMORY_MEMORY_H
#define MEMORY_MEMORY_H

/// 高位 + 偏移量 -> 低位
#define GUEST_MEMORY_OFFSET 0x088800000000ULL
#define TO_HOST(addr)  (addr + GUEST_MEMORY_OFFSET)
#define TO_GUEST(addr) (addr - GUEST_MEMORY_OFFSET)

#define ROUNDDOWN(x, k) ((x) & -(k))
#define ROUNDUP(x, k)   (((x) + (k)-1) & -(k))
#define MIN(x, y)       ((y) > (x) ? (x) : (y))
#define MAX(x, y)       ((y) < (x) ? (x) : (y))



#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>


#include "tools/debug.hpp"
#include "core/loader.hpp"
#include "memory/reg.hpp"



// ============================================================================== //
// 高速缓存 cache
// ============================================================================== //

/// @brief 高速缓存类
class Cache
{
private:

    static const size_t max_cache_entry_size = 64 * 1024;   // 代码块最大存储个数
    static const size_t max_cache_size = 64 * 1024 * 1024;  // 高速缓存大小：64MB


public:

    /// @brief 高速缓存表项
    typedef struct {
        u64 pc;         // 指令计数器  key
        u64 hot;        // 热度值     flag
        u64 offset;     // 偏移量     value
    } cache_item_t;

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

    u64 entry;              // 入口地址
    u64 host_alloc;     // 程序内存分割值：最大segament
    u64 alloc;          // 申请内存地址
    u64 base;           // 基础地址

    MMU() {}
    ~MMU() {}


    // 实现 flags_to_mmap_prot 函数
    static inline int flags_to_mmap_prot(u32 flags) {
        int prot = 0;
        if (flags & (u32)LIEF::ELF::ELF_SEGMENT_FLAGS::PF_R) {
            prot |= PROT_READ;
        }
        if (flags & (u32)LIEF::ELF::ELF_SEGMENT_FLAGS::PF_W) {
            prot |= PROT_WRITE;
        }
        if (flags & (u32)LIEF::ELF::ELF_SEGMENT_FLAGS::PF_X) {
            prot |= PROT_EXEC;
        }
        return prot;
    }

    /// @brief 从二进制文件加载一个段并将其映射到内存中
    /// @param fd 文件标识符
    /// @param segment 段
    void MMU_load_segment(int fd, LIEF::ELF::Segment segment) {
        int page_size = getpagesize();
        u64 offset = segment.file_offset();
        u64 vaddr = TO_HOST(segment.virtual_address());
        u64 aligned_vaddr = ROUNDDOWN(vaddr, page_size);
        u64 filesz = segment.physical_size() + (vaddr - aligned_vaddr);
        u64 memsz = segment.virtual_size() + (vaddr - aligned_vaddr);

        // mmap page aligned: 对齐 page size
        int prot = flags_to_mmap_prot((u32)segment.flags());
        void *addr = mmap((void *)aligned_vaddr, filesz, prot, MAP_PRIVATE | MAP_FIXED,
                          fd, ROUNDDOWN(offset, page_size));
        assert(addr == (void *)aligned_vaddr);
        
        // .bss section
        uint64_t remaining_bss = ROUNDUP(memsz, page_size) - ROUNDUP(filesz, page_size);
        if (remaining_bss > 0) {
            addr = mmap((void *)(aligned_vaddr + ROUNDUP(filesz, page_size)),
                        remaining_bss, prot, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
            assert(addr == (void *)(aligned_vaddr + ROUNDUP(filesz, page_size)));
        }
        
        this->host_alloc = MAX(this->host_alloc, (aligned_vaddr + ROUNDUP(memsz, page_size)));
        this->base = this->alloc = TO_GUEST(this->host_alloc);
    }


    /// @brief 申请内存
    /// @param sz 内存大小
    /// @return 申请内存地址
    u64 MMU_alloc(i64 sz) {
        int page_size = getpagesize();
        u64 base = this->alloc;
        assert(base >= this->base);

        this->alloc += sz;
        assert(this->alloc >= this->base);
        if (sz > 0 && this->alloc > TO_GUEST(this->host_alloc)) {
            if (mmap((void *)this->host_alloc, ROUNDUP(sz, page_size),
                    PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) == MAP_FAILED)
                fatal("mmap failed");
            this->host_alloc += ROUNDUP(sz, page_size);
        } else if (sz < 0 && ROUNDUP(this->alloc, page_size) < TO_GUEST(this->host_alloc)) {
            u64 len = TO_GUEST(this->host_alloc) - ROUNDUP(this->alloc, page_size);
            if (munmap((void *)this->host_alloc, len) == -1)
                fatal(strerror(errno));
            this->host_alloc -= len;
        }

        return base;
    }

    /// @brief 将长度为 len 的 data 数据存入指定内存地址 addr
    /// @param addr 地址
    /// @param data 数据
    /// @param len 数据长度
    inline static void mmu_write(u64 addr, u8 *data, size_t len) {
        memcpy((void *)TO_HOST(addr), (void *)data, len);
    }



    /// @brief 加载 ELF 文件信息
    /// @param elf ELF 二进制格式文件
    void MMU_load_elf(std::unique_ptr<LIEF::ELF::Binary> elf, const std::string& filename)
    {
        // 获取入口地址
        this->entry = elf->entrypoint();
        int fd = open(filename.c_str(), O_RDONLY);
        if (fd == -1) {
            fatal("open elf file failed");
            return;
        }
        // 获取可执行文件的segments
        const auto &segments = elf->segments();
    
        // 遍历ELF文件的segments并将其映射到内存中
        for (const auto &segment : segments)
        {
            if (segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_LOAD)
            {
                MMU_load_segment(fd, segment);
            }
        }

        close(fd);

        return;
    }




};





#endif // MEMORY_MEMORY_H