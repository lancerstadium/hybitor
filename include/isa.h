/**
 * @brief 体系结构指令相关 API 头文件
 * @file include/isa.h
 * @author lancerstadium
 * @date 2023-10-18
*/

#ifndef _HYBITOR_ISA_H_
#define _HYBITOR_ISA_H_

// 位置在：src/isa/$(GUEST_ISA)/include/isa-def.h
#include "isa-def.h"



// ============================================================================ //
// isa-def 结构体类型转换，如：riscv32 + CPU_state --> riscv32_CPU_state 
// ============================================================================ //

typedef concat(CONFIG_GUEST_ARCH, _CPU_state) CPU_state;
typedef concat(CONFIG_GUEST_ARCH, _ISADecodeInfo) ISADecodeInfo;

extern CPU_state cpu;   // 声明 cpu 类型 ==> ARCH_CPU_state， 定义：src/cpu/cpu-exec

// ============================================================================ //
// init API 定义 --> 实现 src/isa/ARCH/init.c
// ============================================================================ //

/// @brief 初始化指令集
void init_isa();

// ============================================================================ //
// reg API 定义 --> 实现 src/isa/ARCH/reg.c
// ============================================================================ //

/// @brief 打印 riscv32寄存器信息
void print_isa_reg_info();

/// @brief riscv32寄存器转换：字符串 → 数值
word_t isa_reg_str2val(const char *name, bool *success);



#endif // _HYBITOR_ISA_H