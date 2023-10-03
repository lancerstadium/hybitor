/**
 * \file include/cpu/cpu.h
 * \brief 模拟cpu
 */


#ifndef CPU_CPU_H
#define CPU_CPU_H


#include "memory/memory.hpp"

/// @brief CPU 状态信息类
class CPU_state
{
private:
    
public:

    /// @brief 跳出循环原因
    enum exit_reason_t {
        none,               // 无原因
        direct_branch,      // 直接跳转
        indirect_branch,    // 间接跳转
        ecall,              // ecall 调用
        interp,             // 需要解释执行：复杂指令，频率低
    } exit_reason;

    u64 reenter_pc;                     // 再次跳入指令的pc值
    u64 gp_regs[32];                    // 通用寄存器
    Reg::gp_reg_type_t fp_regs[32];     // 浮点型寄存器
    u64 pc;                             // 程序计数器：程序当前所在位置


    CPU_state() {}
    ~CPU_state() {}
};


class VM
{
private:
    
public:

    CPU_state state;
    MMU mmu;
    Cache cache;

    VM() {}
    ~VM() {}
};



#endif // CPU_CPU_H