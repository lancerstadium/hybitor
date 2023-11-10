/**
 * @brief riscv64指令定义头文件
 * @file src/isa/riscv64/include/isa-def.h
 * @author lancerstadium
 * @date 2023-10-24
*/

#ifndef _HYBITOR_ISA_RISCV64_INCLUDE_ISA_DEF_H_
#define _HYBITOR_ISA_RISCV64_INCLUDE_ISA_DEF_H_

#include "common.h"

typedef struct {
  word_t gpr[MUXDEF(CONFIG_RVE, 16, 32)];
  vaddr_t pc;
} MUXDEF(CONFIG_RV64, riscv64_CPU_state, riscv32_CPU_state);


typedef struct {
  union {
    uint32_t val;
  } inst;
} MUXDEF(CONFIG_RV64, riscv64_ISADecodeInfo, riscv32_ISADecodeInfo);

#endif // _HYBITOR_ISA_RISCV32_INCLUDE_ISA_DEF_H_
