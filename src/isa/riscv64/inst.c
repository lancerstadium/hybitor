/**
 * @brief 指令集处理头文件
 * @file src/isa/riscv64/inst.h
 * @author lancerstadium
 * @date 2023-10-28
*/

#include "reg.h"
#include "cpu/cpu.h"
#include "cpu/ifetch.h"
#include "cpu/decode.h"


// ============================================================================ //
// inst 模式枚举类
// ============================================================================ //

enum {
  TYPE_I, TYPE_U, TYPE_S,
  TYPE_N, // none
};

// ============================================================================ //
// inst 宏定义
// ============================================================================ //

#define R(i) gpr(i)
#define Mr vaddr_read
#define Mw vaddr_write

#define src1R() do { *src1 = R(rs1); } while (0)
#define src2R() do { *src2 = R(rs2); } while (0)
#define immI() do { *imm = SEXT(BITS(i, 31, 20), 12); } while(0)
#define immU() do { *imm = SEXT(BITS(i, 31, 12), 20) << 12; } while(0)
#define immS() do { *imm = (SEXT(BITS(i, 31, 25), 7) << 5) | BITS(i, 11, 7); } while(0)


/// @brief 解码指令操作
/// @param s 解码器
/// @param rd 
/// @param src1 寄存器地址1
/// @param src2 寄存器地址1=2
/// @param imm 立即数
/// @param type 指令类型
static void decode_operand(Decode *s, int *rd, word_t *src1, word_t *src2, word_t *imm, int type) {
    uint32_t i = s->isa.inst.val;
    int rs1 = BITS(i, 19, 15);
    int rs2 = BITS(i, 24, 20);
    *rd     = BITS(i, 11, 7);
    switch (type) {
        case TYPE_I: src1R();          immI(); break;
        case TYPE_U:                   immU(); break;
        case TYPE_S: src1R(); src2R(); immS(); break;
    }
}

/// @brief 解码器执行
/// @param s 解码器
/// @return 执行状态
static int decode_exec(Decode *s) {
    int rd = 0;
    word_t src1 = 0, src2 = 0, imm = 0;
    s->dnpc = s->snpc;

#define INSTPAT_INST(s) ((s)->isa.inst.val)
#define INSTPAT_MATCH(s, name, type, ... /* execute body */ ) { \
    decode_operand(s, &rd, &src1, &src2, &imm, concat(TYPE_, type)); \
    __VA_ARGS__ ; \
}
    INSTPAT_START();
    INSTPAT("??????? ????? ????? ??? ????? 00101 11", auipc  , U, R(rd) = s->pc + imm);
    INSTPAT("??????? ????? ????? 100 ????? 00000 11", lbu    , I, R(rd) = Mr(src1 + imm, 1));
    INSTPAT("??????? ????? ????? 000 ????? 01000 11", sb     , S, Mw(src1 + imm, 1, src2));

    INSTPAT("0000000 00001 00000 000 00000 11100 11", ebreak , N, HYTRAP(s->pc, R(10))); // R(10) is $a0
    INSTPAT("??????? ????? ????? ??? ????? ????? ??", inv    , N, HYINVALID(s->pc));
    INSTPAT_END();

    R(0) = 0; // reset $zero to 0

    return 0;
}

// ============================================================================ //
// isa API 实现 --> 声明：include/cpu/decode.h
// ============================================================================ //

int isa_exec_once(Decode *s) {
  s->isa.inst.val = inst_fetch(&s->snpc, 4);
  return decode_exec(s);
}
