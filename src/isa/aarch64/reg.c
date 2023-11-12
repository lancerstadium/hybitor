/**
 * @brief aarch64寄存器操作
 * @file src/isa/aarch64/reg.h
 * @author lancerstadium
 * @date 2023-11-12
*/


#include "reg.h"

// ============================================================================ //
// aarch64 reg 静态变量
// ============================================================================ //

/// @brief aarch64寄存器列表
const char *regs[] = {
    "$0", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};

// ============================================================================ //
// aarch64 reg API 实现 --> 声明 src/isa.h
// ============================================================================ //

void print_isa_reg_info() {
    printf("Reg Info: ");
    for (int i = 0; i < REG_SIZE; i++) {
        if (i % 4 == 0) {
            printf("\n  %-3s: " FMT_WORD " , ", reg_name(i), (long unsigned int)gpr(i));
        } else {
            printf("%-3s: " FMT_WORD " , ", reg_name(i), (long unsigned int)gpr(i));
        }
    }
    printf("\n");
}

word_t isa_reg_str2val(const char *name, bool *success) {
    TODO("isa_reg_str2val");
    return 0;
}
