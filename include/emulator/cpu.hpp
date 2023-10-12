/// \file emulator/cpu.hpp
/// \brief RISC-V64 cpu 模拟

#ifndef EMULATOR_CPU_HPP
#define EMULATOR_CPU_HPP



#include "emulator/bus.hpp"
#include "emulator/csr.hpp"
#include "emulator/reg.hpp"
#include "tools/debug.hpp"






// ==================================================================================== //
// CPU
// ==================================================================================== //

#define MAX_REGS_SIZE 32

class CPU {

private:

    char reg_abinames[MAX_REGS_SIZE][5] = {"$0","ra","sp","gp","tp","t0","t1","t2","s0","s1","a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","t3","t4","t5","t6"};

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

    u64 regs[MAX_REGS_SIZE];        // 寄存器
    u64 pc;                         // 指令计数器
    u64 reenter_pc;                 // 
    enum exit_reason_t {
        none,               // 无
        direct_branch,      // 直接跳转
        indirect_branch,    // 间接跳转
        ecall,              // 
        interp,             // 需要解释执行：复杂指令，频率低
    } exit_reason;
    BUS bus;                        // 总线
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
    fp_reg_t fp_regs[num_fp_regs];  // 浮点型寄存器

    /// @brief CPU 构造函数
    CPU() {}
    ~CPU() {}

    /// @brief 获取通用寄存器的值
    /// @param reg 寄存器编号
    /// @return 存储值
    inline u64 cpu_get_gp_reg(i32 reg) {
        assert(reg >= 0 && reg <= num_gp_regs);
        return this->regs[reg];
    }

    /// @brief 设置通用寄存器的值
    /// @param reg 寄存器编号
    /// @param data 设置值
    inline void cpu_set_gp_reg(i32 reg, u64 data) {
        assert(reg >= 0 && reg <= num_gp_regs);
        this->regs[reg] = data;
    }

    void cpu_print_regs() {
        int clo = 4;
        cout << "[REG infomations]" << endl;
        for(int i = 0; i< MAX_REGS_SIZE/clo; i++) {
            for (int j = 0; j < clo; j++)
            {
                int index = clo * i + j;
                if(index >= MAX_REGS_SIZE)
                    return;
                cout << " " << std::setw(2) << std::setfill(' ') << std::right << std::dec << index+1 << " ";
                cout << std::setw(3) << std::right << reg_abinames[index] << ": 0x";
                cout << std::setw(8) << std::setfill('0') << std::left << std::hex << this->regs[index] << " ";
            }
            cout << endl;
        }
        cout << endl;
    }

    void cpu_print_info()
    {
        cout << "[CPU infomations]" << endl;
        cout << "  pc      : " << "0x" << std::hex << std::setw(8) << std::setfill('0') << this->pc << endl;
        cout << "  regs    : " << this->regs << endl;
        cout << "  state   : " << this->state << endl;
        cout << "  priv    : " << this->pri_level << endl;
        cpu_print_regs();
        cout << "[BUS infomations]" << endl;
        this->bus.dram.mem_print_info();
        cout << endl;
    }

    /// @brief 初始化CPU：计数器、寄存器、状态等
    void cpu_init()
    {
        this->exit_reason = none;
        this->pc = RESET_VECTOR;
        this->regs[zero] = 0;
        size_t stack_size = 32 * 1024 * 1024; // 32MB 栈
        u64 mem_stack = this->bus.dram.mem_alloc(stack_size);
        this->regs[CPU::sp] = mem_stack + stack_size; // 栈指针寄存器
        this->state = CPU_RUN;
        this->pri_level = M;
    }

    /// @brief CPU 加载
    /// @param addr 地址
    /// @param length 长度
    /// @return 加载地址
    // u64 cpu_load(u64 addr, int length)
    // {
    //     return this->bus.dram.mem_load(addr, length);
    // }

    /// @brief CPU 存储数据
    /// @param addr 地址
    /// @param length 长度
    /// @param val 值
    // void cpu_store(u64 addr, int length, u64 val)
    // {
    //     this->bus.dram.mem_store(addr, length, val);
    // }

    /// @brief CPU 取指令
    /// @return 指令地址
    u32 cpu_fetch_inst()
    {
        return *(u32 *)TO_HOST(this->pc);
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