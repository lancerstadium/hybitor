/**
 * @brief reg 寄存器头文件
 * @file src/isa/aarch64/include/reg.h
 * @author lancerstadium
 * @date 2023-10-24
*/


#ifndef _HYBITOR_ISA_AARCH64_INCLUDE_REG_H_
#define _HYBITOR_ISA_AARCH64_INCLUDE_REG_H_

#include "isa-def.h"

/**
 * @brief 检查给定的索引是否在寄存器的有效范围内
 * @param idx 要检查的索引
 * @return 索引，如果它是有效的
 */
static inline int check_reg_idx(int idx) {
  IFDEF(CONFIG_RT_CHECK, assert(idx >= 0 && idx < REG_SIZE));
  return idx;
}

/// 获取通用寄存器`idx`处的值
#define gpr(idx) (cpu.gpr[check_reg_idx(idx)])

/**
  * 根据索引返回寄存器的名称
  * @param idx 寄存器的索引
  * @return 寄存器的名称
  */
static inline const char* reg_name(int idx) {
    extern const char* regs[];
    return regs[check_reg_idx(idx)];
}


#endif // _HYBITOR_ISA_AARCH64_INCLUDE_REG_H_