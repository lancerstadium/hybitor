/**
 * \file include/memory/memory.h
 * \brief 模拟memory：寄存器、Cache、内存
 */


#ifndef CPU_STATE_H
#define CPU_STATE_H

#include "tools/types.hpp"
#include "memory/reg.hpp"

// ============================================================================== //
// 状态 state
// ============================================================================== //

/// @brief 跳出内存循环的原因
enum exit_reason_t {
    none,               // 无
    direct_branch,      // 直接跳转
    indirect_branch,    // 间接跳转
    ecall,              // 
    interp,             // 需要解释执行：复杂指令，频率低
};

/// @brief csr寄存器
enum csr_t {
    fflags = 0x001,
    frm    = 0x002,
    fcsr   = 0x003,
};

/// @brief 状态信息结构体
typedef struct {
    enum exit_reason_t exit_reason; // 跳出循环原因
    u64 reenter_pc;                 // 再次跳入指令的pc值
    u64 gp_regs[num_gp_regs];       // 通用寄存器
    fp_reg_t fp_regs[num_fp_regs];  // 浮点型寄存器
    u64 pc;                         // 程序计数器：程序当前所在位置
} state_t;


#endif // CPU_STATE_HPP