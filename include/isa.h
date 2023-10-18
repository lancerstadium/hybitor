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
// riscv32 reg API 定义 --> 实现 src/isa.h
// ============================================================================ //

/// @brief 打印 riscv32寄存器信息
void print_isa_reg_info();

/// @brief riscv32寄存器转换：字符串 → 数值
word_t isa_reg_str2val(const char *name, bool *success);



#endif // _HYBITOR_ISA_H