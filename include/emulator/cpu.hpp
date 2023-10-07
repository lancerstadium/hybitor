/// \file emulator/this->hpp
/// \brief RISC-V64 cpu 模拟

#ifndef EMULATOR_CPU_HPP
#define EMULATOR_CPU_HPP

#include "emulator/bus.hpp"
#include "emulator/csr.hpp"
#include "tools/debug.hpp"


u64 MASK(u64 n) {
    if (n == 64) return ~0ull;
    return (1ull << n) - 1ull;
}
u64 BITS(u64 imm, u64 hi, u64 lo) {
    return (imm >> lo) & MASK(hi - lo + 1ull);
}
u64 SEXT(u64 imm, u64 n) {
    if ((imm >> (n-1)) & 1) {
        printf("the src and res of sext are 0x%llx 0x%llx\n", imm, ((~0ull) << n) | imm);
        return ((~0ull) << n) | imm;
    } else return imm & MASK(n);
}


// ==================================================================================== //
// CPU
// ==================================================================================== //



class CPU {

public:
    enum REG_ABINAME
    {
        zero = 0,
        ra,sp,gp,tp,
        t0,t1,t2,
        s0,s1,
        a0,a1,a2,a3,a4,a5,a6,a7,
        s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,
        t3,t4,t5,t6
    };

    u64 regs[32];       // 寄存器
    u64 pc;             // 指令计数器
    BUS bus;            // 总线
    enum CPU_STATE {
        CPU_STOP,   // CPU 停止
        CPU_RUN,    // CPU 运行
    } state;            // CPU 状态
    enum CPU_PRI_LEVEL {
        U = 0b00,
        S = 0b01,
        M = 0b11,
    } pri_level;    // CPU pri 等级
    CSR csr;        // csr 特权指令

    /// @brief CPU 构造函数
    CPU() {}
    ~CPU() {}

    /// @brief 初始化CPU：计数器、寄存器、状态等
    void cpu_init()
    {
        this->pc = RESET_VECTOR;
        this->regs[0] = 0;
        this->regs[2] = DRAM_BASE + DRAM_SIZE;
        this->state = CPU_RUN;
        this->pri_level = M;
    }

    u64 cpu_load(u64 addr, int length)
    {
        return this->bus.dram.mem_load(addr, length);
    }

    void cpu_store(u64 addr, int length, u64 val)
    {
        this->bus.dram.mem_store(addr, length, val);
    }

    /// @brief CPU 取指令
    /// @return 指令地址
    u64 cpu_fetch_inst()
    {
        return this->cpu_load(this->pc, 4);
    }

    static const enum CPU_PRI_LEVEL cast_to_pre_level(int p)
    {
        if (p == CPU::M)
        {
            return CPU::M;
        }
        else if (p == CPU::S)
        {
            return CPU::S;
        }
        else
        {
            return CPU::U;
        }
    }

    void set_xpp(int cur_lev, int new_xpp)
    {
        switch (cur_lev)
        {
        case S:
            // clear spp
            this->csr.csr[sstatus] &= (-1) ^ (1 << 8);
            // set spp
            this->csr.csr[sstatus] |= (new_xpp << 8);
            break;
        case M:
            // clear mpp
            this->csr.csr[mstatus] &= (-1) ^ (0b11 << 11);
            // set mpp
            this->csr.csr[mstatus] |= (new_xpp << 11);
            break;
        default:
            this->state = CPU_STOP;
            puts("err:U-level call set_xpp\n");
            break;
        }
    }

    u64 get_xpp(int cur_lev)
    {
        switch (cur_lev)
        {
        case S:
            return (get_csr(sstatus) >> 8) & 1;
        case M:
            return (get_csr(mstatus) >> 11) & 0b11;
        default:
            this->state = CPU_STOP;
            puts("err:U-level call get_xpp\n");
            return -1;
        }
    }

    void set_xpie(int cur_lev, int new_xpie)
    {
        switch (cur_lev)
        {
        case S:
            // clear spie
            this->csr.csr[sstatus] &= (-1) ^ (1 << 5);
            // set spie
            this->csr.csr[sstatus] |= (new_xpie << 5);
            break;
        case M:
            // clear mpie
            this->csr.csr[mstatus] &= (-1) ^ (1 << 7);
            // set mpie
            this->csr.csr[mstatus] |= (new_xpie << 7);
            break;
        default:
            this->state = CPU_STOP;
            puts("err:U-level call set_xpie");
            break;
        }
    }

    u64 get_xpie(int cur_lev)
    {
        switch (cur_lev)
        {
        case S:
            return (get_csr(sstatus) >> 5) & 1;
        case M:
            return (get_csr(mstatus) >> 7) & 1;
        default:
            this->state = CPU_STOP;
            puts("err:U-level call get_xpie");
            return -1;
        }
    }

    void set_xie(int cur_lev, int new_xie)
    {
        switch (cur_lev)
        {
        case S:
            // clear sie
            this->csr.csr[sstatus] &= (-1) ^ (1 << 1);
            // set sie
            this->csr.csr[sstatus] |= (new_xie << 1);
            break;
        case M:
            // clear mie
            this->csr.csr[mstatus] &= (-1) ^ (1 << 3);
            // set mie
            this->csr.csr[mstatus] |= (new_xie << 3);
            break;
        default:
            this->state = CPU_STOP;
            puts("err:U-level call set_xie");
            break;
        }
    }

    u64 get_xie(int cur_lev)
    {
        switch (cur_lev)
        {
        case S:
            return BITS(get_csr(sstatus), 1, 1);
        case M:
            return BITS(get_csr(mstatus), 3, 3);
        default:
            this->state = CPU_STOP;
            puts("err:U-level call get_xie");
            return -1;
            break;
        }
    }

    void set_csr(u64 csr_addr, u64 csr_val)
    {
        this->csr.csr[csr_addr] = csr_val;
    }

    u64 get_csr(u64 csr_addr)
    {
        return this->csr.csr[csr_addr];
    }
};











#endif