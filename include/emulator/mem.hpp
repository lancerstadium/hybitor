/// \file emulator/mem.hpp
/// \brief 内存 DRAM 模拟

#ifndef EMULATOR_MEM_HPP
#define EMULATOR_MEM_HPP

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <llvm/BinaryFormat/ELF.h>

#include "tools/types.hpp"
#include "tools/debug.hpp"
#include "core/loader.hpp"

// #define DRAM_SIZE 1024*1024*128ULL   //128 MiB

/// 高位 + 偏移量 -> 低位
#define DRAM_BASE 0x088800000000ULL
#define TO_HOST(addr)  (addr + DRAM_BASE)
#define TO_GUEST(addr) (addr - DRAM_BASE)

#define ROUNDDOWN(x, k) ((x) & -(k))
#define ROUNDUP(x, k)   (((x) + (k)-1) & -(k))
#define MIN(x, y)       ((y) > (x) ? (x) : (y))
#define MAX(x, y)       ((y) < (x) ? (x) : (y))

#ifndef RESET_VECTOR_OFFSET
#define RESET_VECTOR_OFFSET 0
#endif
#define RESET_VECTOR DRAM_BASE + RESET_VECTOR_OFFSET

using namespace llvm::ELF;

/// @brief DRAM 类
class DRAM {
private:

public:
    u64 entry;          // 入口地址
    u64 host_alloc;     // 程序内存分割值：最大segament
    u64 alloc;          // 申请内存地址
    u64 base;           // 基础地址
    u8 *dram_addr;      // 地址

    DRAM() {}
    ~DRAM() {}

// ====================================================================================== //
// DRAM 初始化、申请、加载
// ====================================================================================== //

    /// @brief 初始化 DRAM：申请空间
    // void dram_init() {
    //     this->dram_addr = (u8 *)malloc(DRAM_SIZE);
    //     assert(this->dram_addr);
    // }

    /// @brief DRAM 存储：
    /// eg: `dram_store(0, 4, 0x00000297); --> auipc t0, 0`
    /// @param addr 数据地址
    /// @param length 数据长度
    /// @param val 存储值
    // void dram_store(u64 addr, int length, u64 val) {
    //     printf("dram_addr store 0x%lx\n", (unsigned long)addr);
    //     assert (length == 1 || length == 2 || length == 4 || length == 8);
    //     assert(addr >= 0 && addr < this->alloc);
    //     switch (length) {
    //         case 1:
    //             this->dram_addr[addr] = val & 0xff;
    //             return;
    //         case 2:
    //             this->dram_addr[addr] = val & 0xff;
    //             this->dram_addr[addr + 1] = (val >> 8) & 0xff;
    //             return;
    //         case 4:
    //             this->dram_addr[addr] = val & 0xff;
    //             this->dram_addr[addr + 1] = (val >> 8) & 0xff;
    //             this->dram_addr[addr + 2] = (val >> 16) & 0xff;
    //             this->dram_addr[addr + 3] = (val >> 24) & 0xff;
    //             return;
    //         case 8:
    //             printf("addr+4:0x%llx   addr: 0x%llx\n", addr + 4, addr);
    //             this->dram_store(addr, 4, val & 0xffffffff);
    //             this->dram_store(addr + 4, 4, (val >> 32) & 0xffffffff);
    //             return;
    //     }
    // }

    /// @brief DRAM 加载
    /// @param addr 地址
    /// @param length 长度
    /// @return 地址
    // u64 dram_load(u64 addr, int length)
    // {
    //     assert (length == 1 || length == 2 || length == 4 || length == 8);
    //     if(addr < 0 || addr >= this->alloc) {
    //         fatalf("load addr: %llx , mem alloc addr: %llx", addr, this->alloc);
    //     }
    //     switch (length) {
    //         case 1:
    //             return this->dram_addr[addr];
    //         case 2:
    //             return (((u64)this->dram_addr[addr + 1]) << 8) | (u64)this->dram_addr[addr];
    //         case 4:
    //             return (((u64)this->dram_addr[addr + 3]) << 24) | ((u64)this->dram_addr[addr + 2] << 16) | ((u64)this->dram_addr[addr + 1] << 8) | ((u64)this->dram_addr[addr]);
    //         case 8:
    //             printf("addr+4:0x%llx   addr: 0x%llx\n", this->dram_load(addr + 4, 4), this->dram_load(addr, 4));
    //             return (this->dram_load(addr + 4, 4) << 32) | this->dram_load(addr, 4);
    //     }
    //     return 0;
    // }

// ====================================================================================== //
// 内存申请与加载
// ====================================================================================== //


    /// @brief 内存加载
    /// @param addr 地址
    /// @param length 长度
    /// @return 加载地址
    // u64 mem_load(u64 addr, int length)
    // {
    //     u64 res = this->dram_load(addr - DRAM_BASE, length);
    //     printf("mem load addr = 0x%08lx, res = 0x%llx\n", (unsigned long)addr, res);
    //     return res;
    // }

    /// @brief 内存存储
    /// @param addr 地址
    /// @param length 长度
    /// @param val 值
    // void mem_store(u64 addr, int length, u64 val)
    // {
    //     this->dram_store(addr - DRAM_BASE, length, val);
    // }

    /// @brief 内存申请
    /// @param sz 申请大小
    /// @return base地址
    u64 mem_alloc(i64 sz) {
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
    inline void mem_write(u64 addr, u8 *data, size_t len) {
        memcpy((void *)TO_HOST(addr), (void *)data, len);
    }


// ====================================================================================== //
// 静态工具函数
// ====================================================================================== //

    /// @brief 匹配 segment 类型
    /// @param flags phdr 类型符号
    /// @return segment 类型
    static int flags_to_mmap_prot(u32 flags)
    {
        return (flags & PF_R ? PROT_READ : 0) |
               (flags & PF_W ? PROT_WRITE : 0) |
               (flags & PF_X ? PROT_EXEC : 0);
    }

    /// @brief 加载 program header 对象
    /// @param phdr program header 对象
    /// @param ehdr elf header 对象
    /// @param i 第 i 个 program header
    /// @param file 文件对象
    static void mem_load_phdr(Elf64_Phdr &phdr, Elf64_Ehdr &ehdr, i64 i, FILE *file)
    {
        // 找到第 i 个 program header 偏移量
        if(fseek(file, ehdr.e_phoff + ehdr.e_phentsize * i, SEEK_SET) != 0) {
            fatal("seek file failed");
        }
        // 加载到指针 phdr 中
        if(fread((void *)&phdr, 1, sizeof(Elf64_Phdr), file) != sizeof(Elf64_Phdr)) {
            fatal("file's Phdr too small");
        }
    }

    /// @brief 加载 program header 的 segment 到内存
    /// @param phdr program header 对象
    /// @param fd 文件标识符
    void mem_load_segment(Elf64_Phdr &phdr, int fd)
    {
        int page_size = getpagesize();          // 获取页面大小
        u64 offset = phdr.p_offset;             // 获取偏移量
        u64 vaddr = TO_HOST(phdr.p_vaddr);      // 主机虚拟地址
        u64 aligned_vaddr = ROUNDDOWN(vaddr, page_size);
        u64 filesz = phdr.p_filesz + (vaddr - aligned_vaddr);
        u64 memsz = phdr.p_memsz + (vaddr - aligned_vaddr);

        // mmap page aligned: 对齐 page size
        int prot = flags_to_mmap_prot(phdr.p_flags);
        u64 addr = (u64)mmap((void *)aligned_vaddr, filesz, prot, MAP_PRIVATE | MAP_FIXED, 
                            fd, ROUNDDOWN(offset, page_size));
        assert(addr == aligned_vaddr);

        // .bss section
        u64 remaining_bss = ROUNDUP(memsz, page_size) - ROUNDUP(filesz, page_size);
        if (remaining_bss > 0) {
            u64 addr = (u64)mmap((void *)(aligned_vaddr + ROUNDUP(filesz, page_size)),
                remaining_bss, prot, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
            assert(addr == aligned_vaddr + ROUNDUP(filesz, page_size));
        }

        this->host_alloc = MAX(this->host_alloc, (aligned_vaddr + ROUNDUP(memsz, page_size)));
        this->base = this->alloc = TO_GUEST(this->host_alloc);
    }
    


// ====================================================================================== //
// 文件加载到内存
// ====================================================================================== //


    /// @brief 内存加载 ELF 二进制文件
    /// @param fd 文件标识符
    void mem_load_elf(int fd)
    {

        // 读取二进制文件
        FILE *file = fdopen(fd, "rb"); 
        assert(file);
        
        // elf 头部
        Elf64_Ehdr ehdr;
        fread(&ehdr, sizeof(Elf64_Ehdr), 1, file);

        // 检查文件魔法数
        if(!ehdr.checkMagic()) {        
            fatal("not elf file");
        }
        
        // 检查ELF文件是否64位
        if(ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
            cout << "ELF class: 32-bits " << endl;
            fatal("now 32-bit elf file is not supported");
        } else if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
            cout << "ELF class: 64-bits " << endl;
        } else {
            fatal("Unknow ELF class");
        }

        // 检查文件体系架构
        cout << "Architecture: ";
        switch (ehdr.e_machine)
        {
        case EM_RISCV: cout << "RISCV" << endl; break;
        case EM_X86_64: cout << "X86_64" << endl; break;
        case EM_AARCH64: cout << "AARCH64" << endl; break;
        default: cout << "Unknown" << endl; break;
        }
        
        // 获取入口地址
        this->entry = (u64)ehdr.e_entry;

        cout << "Loading elf file ..." << endl;
        Elf64_Phdr phdr;
        // 寻找 program 头部
        for (i64 i = 0; i < ehdr.e_phnum; i++)
        {
            mem_load_phdr(phdr, ehdr, i, file);
            // 将phdr加载到内存
            if (phdr.p_type == PT_LOAD) {
                mem_load_segment(phdr, fd);
            }
        }
        cout << "Load elf file success" << endl;
        mem_print_info();
    }

    /// @brief 打印 dram 信息
    void mem_print_info()
    {
        cout << "|-[mem infomations]" << endl;
        cout << "    entry addr      : " << "0x" << std::hex << this->entry << endl;
        cout << "    base addr       : " << "0x" << std::hex << this->base << endl;
        cout << "    alloc addr      : " << "0x" << std::hex << this->alloc << endl;
        cout << "    host alloc addr : " << "0x" << std::hex << this->host_alloc << endl;
    }

    /// @brief 内存加载二进制文件
    /// @param fd 文件标识符
    void mem_load_file(int fd)
    {
        // 读取二进制文件
        FILE *file = fdopen(fd, "rb"); 
        assert(file);
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        printf("Read %ld byte from file.\n", size);
        fseek(file, 0, SEEK_SET);
        fread(this->dram_addr + RESET_VECTOR_OFFSET, size, 1, file);
    }

};





#endif // EMULATOR_MEM_HPP