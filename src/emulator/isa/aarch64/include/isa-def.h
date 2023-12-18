/**
 * @brief aarch64指令定义头文件
 * @file src/isa/aarch64/include/isa-def.h
 * @author lancerstadium
 * @date 2023-10-24
*/

#ifndef _HYBITOR_ISA_AARCH64_INCLUDE_ISA_DEF_H_
#define _HYBITOR_ISA_AARCH64_INCLUDE_ISA_DEF_H_

#include "common.h"

#define REG_SIZE 32

typedef struct {
    word_t gpr[REG_SIZE];
    vaddr_t pc;
} MUXDEF(CONFIG_ARM64, aarch64_CPU_state, aarch32_CPU_state);


typedef struct {
    union {
        uint32_t val;
    } inst;
} MUXDEF(CONFIG_ARM64, aarch64_ISADecodeInfo, aarch32_ISADecodeInfo);

#endif // _HYBITOR_ISA_RISCV32_INCLUDE_ISA_DEF_H_
