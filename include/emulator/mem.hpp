/// \file emulator/mem.hpp
/// \brief 内存 DRAM 模拟

#ifndef EMULATOR_MEM_HPP
#define EMULATOR_MEM_HPP

#include "tools/types.hpp"
#include "tools/debug.hpp"

#define DRAM_SIZE 1024*1024*128ull   //128 MiB
#define DRAM_BASE 0x80000000ull
#ifndef RESET_VECTOR_OFFSET
#define RESET_VECTOR_OFFSET 0
#endif
#define RESET_VECTOR DRAM_BASE + RESET_VECTOR_OFFSET

/// @brief DRAM 类
class DRAM {
private:

public:
    u8 *dram;  // 地址

    /// @brief 初始化 DRAM：申请空间
    void dram_init() {
        this->dram = (u8 *)malloc(DRAM_SIZE);
        assert(this->dram);
    }

    /// @brief DRAM 存储：
    /// eg: `dram_store(0, 4, 0x00000297); --> auipc t0, 0`
    /// @param addr 数据地址
    /// @param length 数据长度
    /// @param val 存储值
    void dram_store(u64 addr, int length, u64 val) {
        printf("dram store 0x%lx\n", (unsigned long)addr);
        assert (length == 1 || length == 2 || length == 4 || length == 8);
        assert(addr >= 0 && addr < DRAM_SIZE);
        switch (length) {
            case 1:
                this->dram[addr] = val & 0xff;
                return;
            case 2:
                this->dram[addr] = val & 0xff;
                this->dram[addr + 1] = (val >> 8) & 0xff;
                return;
            case 4:
                this->dram[addr] = val & 0xff;
                this->dram[addr + 1] = (val >> 8) & 0xff;
                this->dram[addr + 2] = (val >> 16) & 0xff;
                this->dram[addr + 3] = (val >> 24) & 0xff;
                return;
            case 8:
                printf("addr+4:0x%llx   addr: 0x%llx\n", addr + 4, addr);
                this->dram_store(addr, 4, val & 0xffffffff);
                this->dram_store(addr + 4, 4, (val >> 32) & 0xffffffff);
                return;
        }
    }

    /// @brief DRAM 加载
    /// @param addr 地址
    /// @param length 长度
    /// @return 地址
    u64 dram_load(u64 addr, int length)
    {
        assert (length == 1 || length == 2 || length == 4 || length == 8);
        assert(addr >= 0 && addr < DRAM_SIZE);
        switch (length) {
            case 1:
                return this->dram[addr];
            case 2:
                return (((u64)this->dram[addr + 1]) << 8) | (u64)this->dram[addr];
            case 4:
                return (((u64)this->dram[addr + 3]) << 24) | ((u64)this->dram[addr + 2] << 16) | ((u64)this->dram[addr + 1] << 8) | ((u64)this->dram[addr]);
            case 8:
                printf("addr+4:0x%llx   addr: 0x%llx\n", this->dram_load(addr + 4, 4), this->dram_load(addr, 4));
                return (this->dram_load(addr + 4, 4) << 32) | this->dram_load(addr, 4);
        }
        return 0;
    }


    /// @brief 内存加载
    /// @param addr 地址
    /// @param length 长度
    /// @return 加载地址
    u64 mem_load(u64 addr, int length)
    {
        u64 res = this->dram_load(addr - DRAM_BASE, length);
        printf("mem load addr = 0x%08lx, res = 0x%llx\n", (unsigned long)addr, res);
        return res;
    }

    /// @brief 内存存储
    /// @param addr 地址
    /// @param length 长度
    /// @param val 值
    void mem_store(u64 addr, int length, u64 val)
    {
        this->dram_store(addr - DRAM_BASE, length, val);
    }

};





#endif // EMULATOR_MEM_HPP