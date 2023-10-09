/// \file emulator/interpreter.hpp
/// \brief RISC-V64 interpreter 模拟

#ifndef EMULATOR_INTERPRETER_HPP
#define EMULATOR_INTERPRETER_HPP

#include "emulator/decoder.hpp"
#include "emulator/trap.hpp"
#include "emulator/interp_util.hpp"


/// 空函数
static void func_empty(CPU &host_cpu, insn_t *insn) {}

/// 函数指针
typedef void (func_t)(CPU &, insn_t *);


// ============================================================================== //
// 函数实现
// ============================================================================== //

#define FUNC(typ)                                          \
    u64 addr = host_cpu.regs[insn->rs1] + (i64)insn->imm; \
    host_cpu.regs[insn->rd] = *(typ *)TO_HOST(addr);      \

/**
 * NO.1
 * ```
 * lb -> load byte
 * lb a1, 4   (a0)
 *    ra  imm  rs1
 * ra = (i8)[rs1 + imm]
 * ```
 */
static void func_lb(CPU &host_cpu, insn_t *insn) {
    FUNC(i8);
}

static void func_lh(CPU &host_cpu, insn_t *insn) {
    FUNC(i16);
}

/**
 * NO.3
 * ```
 * lw -> load word
 * lw a1, 4   (a0)
 *    ra  imm  rs1
 * ra = (i32)[rs1 + imm]
 * ```
 */
static void func_lw(CPU &host_cpu, insn_t *insn) {
    FUNC(i32);
}

static void func_ld(CPU &host_cpu, insn_t *insn) {
    FUNC(i64);
}

/**
 * NO.5
 * ```
 * lbu -> load byte unsigned
 * lbu a1, 4   (a0)
 *     ra  imm  rs1
 * ra = (u8)[rs1 + imm]
 * ```
 */
static void func_lbu(CPU &host_cpu, insn_t *insn) {
    FUNC(u8);
}

static void func_lhu(CPU &host_cpu, insn_t *insn) {
    FUNC(u16);
}

static void func_lwu(CPU &host_cpu, insn_t *insn) {
    FUNC(u32);
}

#undef FUNC

#define FUNC(expr)                       \
    u64 rs1 = host_cpu.regs[insn->rs1]; \
    i64 imm = (i64)insn->imm;            \
    host_cpu.regs[insn->rd] = (expr);   \

static void func_addi(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 + imm);
}

static void func_slli(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 << (imm & 0x3f));
}

static void func_slti(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)rs1 < (i64)imm);
}

static void func_sltiu(CPU &host_cpu, insn_t *insn) {
    FUNC((u64)rs1 < (u64)imm);
}

static void func_xori(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 ^ imm);
}

static void func_srli(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 >> (imm & 0x3f));
}

static void func_srai(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)rs1 >> (imm & 0x3f));
}

static void func_ori(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 | (u64)imm);
}

static void func_andi(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 & (u64)imm);
}

static void func_addiw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)(rs1 + imm));
}

static void func_slliw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)(rs1 << (imm & 0x1f)));
}

static void func_srliw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)((u32)rs1 >> (imm & 0x1f)));
}

static void func_sraiw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)((i32)rs1 >> (imm & 0x1f)));
}

#undef FUNC

static void func_auipc(CPU &host_cpu, insn_t *insn) {
    u64 val = host_cpu.pc + (i64)insn->imm;
    host_cpu.regs[insn->rd] = val;
}

#define FUNC(typ)                                \
    u64 rs1 = host_cpu.regs[insn->rs1];         \
    u64 rs2 = host_cpu.regs[insn->rs2];         \
    *(typ *)TO_HOST(rs1 + insn->imm) = (typ)rs2; \

static void func_sb(CPU &host_cpu, insn_t *insn) {
    FUNC(u8);
}

static void func_sh(CPU &host_cpu, insn_t *insn) {
    FUNC(u16);
}

static void func_sw(CPU &host_cpu, insn_t *insn) {
    FUNC(u32);
}

static void func_sd(CPU &host_cpu, insn_t *insn) {
    FUNC(u64);
}

#undef FUNC

#define FUNC(expr) \
    u64 rs1 = host_cpu.regs[insn->rs1]; \
    u64 rs2 = host_cpu.regs[insn->rs2]; \
    host_cpu.regs[insn->rd] = (expr);   \

static void func_add(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 + rs2);
}

static void func_sll(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 << (rs2 & 0x3f));
}

static void func_slt(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)rs1 < (i64)rs2);
}

static void func_sltu(CPU &host_cpu, insn_t *insn) {
    FUNC((u64)rs1 < (u64)rs2);
}

static void func_xor(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 ^ rs2);
}

static void func_srl(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 >> (rs2 & 0x3f));
}

static void func_or(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 | rs2);
}

static void func_and(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 & rs2);
}

static void func_mul(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 * rs2);
}

static void func_mulh(CPU &host_cpu, insn_t *insn) {
    FUNC(mulh(rs1, rs2));
}

static void func_mulhsu(CPU &host_cpu, insn_t *insn) {
    FUNC(mulhsu(rs1, rs2));
}

static void func_mulhu(CPU &host_cpu, insn_t *insn) {
    FUNC(mulhu(rs1, rs2));
}

static void func_sub(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 - rs2);
}

static void func_sra(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)rs1 >> (rs2 & 0x3f));
}

static void func_remu(CPU &host_cpu, insn_t *insn) {
    FUNC(rs2 == 0 ? rs1 : rs1 % rs2);
}

static void func_addw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)(rs1 + rs2));
}

static void func_sllw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)(rs1 << (rs2 & 0x1f)));
}

static void func_srlw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)((u32)rs1 >> (rs2 & 0x1f)));
}

static void func_mulw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)(rs1 * rs2));
}

static void func_divw(CPU &host_cpu, insn_t *insn) {
    FUNC(rs2 == 0 ? UINT64_MAX : (i32)((i64)(i32)rs1 / (i64)(i32)rs2));
}

static void func_divuw(CPU &host_cpu, insn_t *insn) {
    FUNC(rs2 == 0 ? UINT64_MAX : (i32)((u32)rs1 / (u32)rs2));
}

static void func_remw(CPU &host_cpu, insn_t *insn) {
    FUNC(rs2 == 0 ? (i64)(i32)rs1 : (i64)(i32)((i64)(i32)rs1 % (i64)(i32)rs2));
}

static void func_remuw(CPU &host_cpu, insn_t *insn) {
    FUNC(rs2 == 0 ? (i64)(i32)(u32)rs1 : (i64)(i32)((u32)rs1 % (u32)rs2));
}

static void func_subw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)(rs1 - rs2));
}

static void func_sraw(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)(i32)((i32)rs1 >> (rs2 & 0x1f)));
}

#undef FUNC

static void func_div(CPU &host_cpu, insn_t *insn) {
    u64 rs1 = host_cpu.regs[insn->rs1];
    u64 rs2 = host_cpu.regs[insn->rs2];
    u64 rd = 0;
    if (rs2 == 0) {
        rd = UINT64_MAX;
    } else if (rs1 == INT64_MIN && rs2 == UINT64_MAX) {
        rd = INT64_MIN;
    } else {
        rd = (i64)rs1 / (i64)rs2;
    }
    host_cpu.regs[insn->rd] = rd;
}

static void func_divu(CPU &host_cpu, insn_t *insn) {
    u64 rs1 = host_cpu.regs[insn->rs1];
    u64 rs2 = host_cpu.regs[insn->rs2];
    u64 rd = 0;
    if (rs2 == 0) {
        rd = UINT64_MAX;
    } else {
        rd = rs1 / rs2;
    }
    host_cpu.regs[insn->rd] = rd;
}

static void func_rem(CPU &host_cpu, insn_t *insn) {
    u64 rs1 = host_cpu.regs[insn->rs1];
    u64 rs2 = host_cpu.regs[insn->rs2];
    u64 rd = 0;
    if (rs2 == 0) {
        rd = rs1;
    } else if (rs1 == INT64_MIN && rs2 == UINT64_MAX) {
        rd = 0;
    } else {
        rd = (i64)rs1 % (i64)rs2;
    }
    host_cpu.regs[insn->rd] = rd;
}

static void func_lui(CPU &host_cpu, insn_t *insn) {
    host_cpu.regs[insn->rd] = (i64)insn->imm;
}

#define FUNC(expr)                                   \
    u64 rs1 = host_cpu.regs[insn->rs1];             \
    u64 rs2 = host_cpu.regs[insn->rs2];             \
    u64 target_addr = host_cpu.pc + (i64)insn->imm;    \
    if (expr) {                                      \
        host_cpu.reenter_pc = host_cpu.pc = target_addr; \
        host_cpu.exit_reason = CPU::direct_branch;          \
        insn->cont = true;                           \
    }                                                \

static void func_beq(CPU &host_cpu, insn_t *insn) {
    FUNC((u64)rs1 == (u64)rs2);
}

static void func_bne(CPU &host_cpu, insn_t *insn) {
    FUNC((u64)rs1 != (u64)rs2);
}

static void func_blt(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)rs1 < (i64)rs2);
}

static void func_bge(CPU &host_cpu, insn_t *insn) {
    FUNC((i64)rs1 >= (i64)rs2);
}

static void func_bltu(CPU &host_cpu, insn_t *insn) {
    FUNC((u64)rs1 < (u64)rs2);
}

static void func_bgeu(CPU &host_cpu, insn_t *insn) {
    FUNC((u64)rs1 >= (u64)rs2);
}

#undef FUNC

static void func_jalr(CPU &host_cpu, insn_t *insn) {
    u64 rs1 = host_cpu.regs[insn->rs1];
    host_cpu.regs[insn->rd] = host_cpu.pc + (insn->rvc ? 2 : 4);
    host_cpu.exit_reason = CPU::indirect_branch;
    host_cpu.reenter_pc = (rs1 + (i64)insn->imm) & ~(u64)1;
}

static void func_jal(CPU &host_cpu, insn_t *insn) {
    host_cpu.regs[insn->rd] = host_cpu.pc + (insn->rvc ? 2 : 4);
    host_cpu.reenter_pc = host_cpu.pc = host_cpu.pc + (i64)insn->imm;
    host_cpu.exit_reason = CPU::direct_branch;
}

static void func_ecall(CPU &host_cpu, insn_t *insn) {
    host_cpu.exit_reason = CPU::ecall;
    host_cpu.reenter_pc = host_cpu.pc + 4;
}

/**
 * TODO: softfloat实现
*/
#define FUNC()                         \
    switch (insn->csr) {               \
    case fflags:                       \
    case frm:                          \
    case fcsr:                         \
        break;                         \
    default: fatal("unsupported csr"); \
    }                                  \
    host_cpu.regs[insn->rd] = 0;      \

static void func_csrrw(CPU &host_cpu, insn_t *insn) { FUNC(); }
static void func_csrrs(CPU &host_cpu, insn_t *insn) { FUNC(); }
static void func_csrrc(CPU &host_cpu, insn_t *insn) { FUNC(); }
static void func_csrrwi(CPU &host_cpu, insn_t *insn) { FUNC(); }
static void func_csrrsi(CPU &host_cpu, insn_t *insn) { FUNC(); }
static void func_csrrci(CPU &host_cpu, insn_t *insn) { FUNC(); }

#undef FUNC

static void func_flw(CPU &host_cpu, insn_t *insn) {
    u64 addr = host_cpu.regs[insn->rs1] + (i64)insn->imm;
    host_cpu.fp_regs[insn->rd].v = *(u32 *)TO_HOST(addr) | ((u64)-1 << 32);
}
static void func_fld(CPU &host_cpu, insn_t *insn) {
    u64 addr = host_cpu.regs[insn->rs1] + (i64)insn->imm;
    host_cpu.fp_regs[insn->rd].v = *(u64 *)TO_HOST(addr);
}

#define FUNC(typ)                                \
    u64 rs1 = host_cpu.regs[insn->rs1];         \
    u64 rs2 = host_cpu.fp_regs[insn->rs2].v;       \
    *(typ *)TO_HOST(rs1 + insn->imm) = (typ)rs2; \

static void func_fsw(CPU &host_cpu, insn_t *insn) {
    FUNC(u32);
}
static void func_fsd(CPU &host_cpu, insn_t *insn) {
    FUNC(u64);
}

#undef FUNC

#define FUNC(expr)                            \
    f32 rs1 = host_cpu.fp_regs[insn->rs1].f;    \
    f32 rs2 = host_cpu.fp_regs[insn->rs2].f;    \
    f32 rs3 = host_cpu.fp_regs[insn->rs3].f;    \
    host_cpu.fp_regs[insn->rd].f = (f32)(expr); \

static void func_fmadd_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 * rs2 + rs3);
}

static void func_fmsub_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 * rs2 - rs3);
}

static void func_fnmsub_s(CPU &host_cpu, insn_t *insn) {
    FUNC(-(rs1 * rs2) + rs3);
}

static void func_fnmadd_s(CPU &host_cpu, insn_t *insn) {
    FUNC(-(rs1 * rs2) - rs3);
}

#undef FUNC

#define FUNC(expr)                         \
    f64 rs1 = host_cpu.fp_regs[insn->rs1].d; \
    f64 rs2 = host_cpu.fp_regs[insn->rs2].d; \
    f64 rs3 = host_cpu.fp_regs[insn->rs3].d; \
    host_cpu.fp_regs[insn->rd].d = (expr);   \

static void func_fmadd_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 * rs2 + rs3);
}
static void func_fmsub_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 * rs2 - rs3);
}
static void func_fnmsub_d(CPU &host_cpu, insn_t *insn) {
    FUNC(-(rs1 * rs2) + rs3);
}
static void func_fnmadd_d(CPU &host_cpu, insn_t *insn) {
    FUNC(-(rs1 * rs2) - rs3);
}

#undef FUNC

#define FUNC(expr)                                                 \
    f32 rs1 = host_cpu.fp_regs[insn->rs1].f;                         \
    __attribute__((unused)) f32 rs2 = host_cpu.fp_regs[insn->rs2].f; \
    host_cpu.fp_regs[insn->rd].f = (f32)(expr);                      \

/**
 * TODO: softfloat fadd(rs1 + rs2)
 * 1. simple
 * 2. prefemance
 */
static void func_fadd_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 + rs2);
}

static void func_fsub_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 - rs2);
}

static void func_fmul_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 * rs2);
}

static void func_fdiv_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 / rs2);
}

static void func_fsqrt_s(CPU &host_cpu, insn_t *insn) {
    FUNC(sqrtf(rs1));
}

static void func_fmin_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 < rs2 ? rs1 : rs2);
}
static void func_fmax_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 > rs2 ? rs1 : rs2);
}

#undef FUNC

#define FUNC(expr)                                                 \
    f64 rs1 = host_cpu.fp_regs[insn->rs1].d;                         \
    __attribute__((unused)) f64 rs2 = host_cpu.fp_regs[insn->rs2].d; \
    host_cpu.fp_regs[insn->rd].d = (expr);                           \

static void func_fadd_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 + rs2);
}

static void func_fsub_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 - rs2);
}

static void func_fmul_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 * rs2);
}

static void func_fdiv_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 / rs2);
}

static void func_fsqrt_d(CPU &host_cpu, insn_t *insn) {
    FUNC(sqrt(rs1));
}

static void func_fmin_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 < rs2 ? rs1 : rs2);
}

static void func_fmax_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 > rs2 ? rs1 : rs2);
}

#undef FUNC

#define FUNC(n, x)                                                                    \
    u32 rs1 = host_cpu.fp_regs[insn->rs1].w;                                            \
    u32 rs2 = host_cpu.fp_regs[insn->rs2].w;                                            \
    host_cpu.fp_regs[insn->rd].v = (u64)fsgnj32(rs1, rs2, n, x) | ((uint64_t)-1 << 32); \

static void func_fsgnj_s(CPU &host_cpu, insn_t *insn) {
    FUNC(false, false);
}

static void func_fsgnjn_s(CPU &host_cpu, insn_t *insn) {
    FUNC(true, false);
}

static void func_fsgnjx_s(CPU &host_cpu, insn_t *insn) {
    FUNC(false, true);
}

#undef FUNC

#define FUNC(n, x)                                        \
    u64 rs1 = host_cpu.fp_regs[insn->rs1].v;                \
    u64 rs2 = host_cpu.fp_regs[insn->rs2].v;                \
    host_cpu.fp_regs[insn->rd].v = fsgnj64(rs1, rs2, n, x); \

static void func_fsgnj_d(CPU &host_cpu, insn_t *insn) {
    FUNC(false, false);
}
static void func_fsgnjn_d(CPU &host_cpu, insn_t *insn) {
    FUNC(true, false);
}
static void func_fsgnjx_d(CPU &host_cpu, insn_t *insn) {
    FUNC(false, true);
}

#undef FUNC

static void func_fcvt_w_s(CPU &host_cpu, insn_t *insn) {
    host_cpu.regs[insn->rd] = (i64)(i32)llrintf(host_cpu.fp_regs[insn->rs1].f);
}

static void func_fcvt_wu_s(CPU &host_cpu, insn_t *insn) {
    host_cpu.regs[insn->rd] = (i64)(i32)(u32)llrintf(host_cpu.fp_regs[insn->rs1].f);
}

static void func_fcvt_w_d(CPU &host_cpu, insn_t *insn) {
    host_cpu.regs[insn->rd] = (i64)(i32)llrint(host_cpu.fp_regs[insn->rs1].d);
}

static void func_fcvt_wu_d(CPU &host_cpu, insn_t *insn) {
    host_cpu.regs[insn->rd] = (i64)(i32)(u32)llrint(host_cpu.fp_regs[insn->rs1].d);
}

static void func_fcvt_s_w(CPU &host_cpu, insn_t *insn) {
    host_cpu.fp_regs[insn->rd].f = (f32)(i32)host_cpu.regs[insn->rs1];
}

static void func_fcvt_s_wu(CPU &host_cpu, insn_t *insn) {
    host_cpu.fp_regs[insn->rd].f = (f32)(u32)host_cpu.regs[insn->rs1];
}

static void func_fcvt_d_w(CPU &host_cpu, insn_t *insn) {
    host_cpu.fp_regs[insn->rd].d = (f64)(i32)host_cpu.regs[insn->rs1];
}

static void func_fcvt_d_wu(CPU &host_cpu, insn_t *insn) {
    host_cpu.fp_regs[insn->rd].d = (f64)(u32)host_cpu.regs[insn->rs1];
}

static void func_fmv_x_w(CPU &host_cpu, insn_t *insn) {
    host_cpu.regs[insn->rd] = (i64)(i32)host_cpu.fp_regs[insn->rs1].w;
}
static void func_fmv_w_x(CPU &host_cpu, insn_t *insn) {
    host_cpu.fp_regs[insn->rd].w = (u32)host_cpu.regs[insn->rs1];
}

static void func_fmv_x_d(CPU &host_cpu, insn_t *insn) {
    host_cpu.regs[insn->rd] = host_cpu.fp_regs[insn->rs1].v;
}

static void func_fmv_d_x(CPU &host_cpu, insn_t *insn) {
    host_cpu.fp_regs[insn->rd].v = host_cpu.regs[insn->rs1];
}

#define FUNC(expr)                         \
    f32 rs1 = host_cpu.fp_regs[insn->rs1].f; \
    f32 rs2 = host_cpu.fp_regs[insn->rs2].f; \
    host_cpu.regs[insn->rd] = (expr);     \

static void func_feq_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 == rs2);
}

static void func_flt_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 < rs2);
}

static void func_fle_s(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 <= rs2);
}

#undef FUNC

#define FUNC(expr)                         \
    f64 rs1 = host_cpu.fp_regs[insn->rs1].d; \
    f64 rs2 = host_cpu.fp_regs[insn->rs2].d; \
    host_cpu.regs[insn->rd] = (expr);     \

static void func_feq_d(CPU &host_cpu, insn_t *insn) {
    FUNC(rs1 == rs2);
}

static void func_flt_d(CPU &host_cpu, insn_t *insn)
{
    FUNC(rs1 < rs2);
}

static void func_fle_d(CPU &host_cpu, insn_t *insn)
{
    FUNC(rs1 <= rs2);
}

#undef FUNC

static void func_fclass_s(CPU &host_cpu, insn_t *insn)
{
    host_cpu.regs[insn->rd] = f32_classify(host_cpu.fp_regs[insn->rs1].f);
}

static void func_fclass_d(CPU &host_cpu, insn_t *insn)
{
    host_cpu.regs[insn->rd] = f64_classify(host_cpu.fp_regs[insn->rs1].d);
}

static void func_fcvt_l_s(CPU &host_cpu, insn_t *insn)
{
    host_cpu.regs[insn->rd] = (i64)llrintf(host_cpu.fp_regs[insn->rs1].f);
}

static void func_fcvt_lu_s(CPU &host_cpu, insn_t *insn)
{
    host_cpu.regs[insn->rd] = (u64)llrintf(host_cpu.fp_regs[insn->rs1].f);
}

static void func_fcvt_l_d(CPU &host_cpu, insn_t *insn)
{
    host_cpu.regs[insn->rd] = (i64)llrint(host_cpu.fp_regs[insn->rs1].d);
}

static void func_fcvt_lu_d(CPU &host_cpu, insn_t *insn)
{
    host_cpu.regs[insn->rd] = (u64)llrint(host_cpu.fp_regs[insn->rs1].d);
}

static void func_fcvt_s_l(CPU &host_cpu, insn_t *insn)
{
    host_cpu.fp_regs[insn->rd].f = (f32)(i64)host_cpu.regs[insn->rs1];
}

static void func_fcvt_s_lu(CPU &host_cpu, insn_t *insn)
{
    host_cpu.fp_regs[insn->rd].f = (f32)(u64)host_cpu.regs[insn->rs1];
}

static void func_fcvt_d_l(CPU &host_cpu, insn_t *insn)
{
    host_cpu.fp_regs[insn->rd].d = (f64)(i64)host_cpu.regs[insn->rs1];
}

static void func_fcvt_d_lu(CPU &host_cpu, insn_t *insn)
{
    host_cpu.fp_regs[insn->rd].d = (f64)(u64)host_cpu.regs[insn->rs1];
}

static void func_fcvt_s_d(CPU &host_cpu, insn_t *insn)
{
    host_cpu.fp_regs[insn->rd].f = (f32)host_cpu.fp_regs[insn->rs1].d;
}

static void func_fcvt_d_s(CPU &host_cpu, insn_t *insn)
{
    host_cpu.fp_regs[insn->rd].d = (f64)host_cpu.fp_regs[insn->rs1].f;
}

// ============================================================================== //
// 函数列表
// ============================================================================== //

/// 匹配执行函数
static func_t *funcs[] = {
    func_lb,
    func_lh,
    func_lw,
    func_ld,
    func_lbu,
    func_lhu,
    func_lwu,
    func_empty, // fence
    func_empty, // fence_i
    func_addi,
    func_slli,
    func_slti,
    func_sltiu,
    func_xori,
    func_srli,
    func_srai,
    func_ori,
    func_andi,
    func_auipc,
    func_addiw,
    func_slliw,
    func_srliw,
    func_sraiw,
    func_sb,
    func_sh,
    func_sw,
    func_sd,
    func_add,
    func_sll,
    func_slt,
    func_sltu,
    func_xor,
    func_srl,
    func_or,
    func_and,
    func_mul,
    func_mulh,
    func_mulhsu,
    func_mulhu,
    func_div,
    func_divu,
    func_rem,
    func_remu,
    func_sub,
    func_sra,
    func_lui,
    func_addw,
    func_sllw,
    func_srlw,
    func_mulw,
    func_divw,
    func_divuw,
    func_remw,
    func_remuw,
    func_subw,
    func_sraw,
    func_beq,
    func_bne,
    func_blt,
    func_bge,
    func_bltu,
    func_bgeu,
    func_jalr,
    func_jal,
    func_ecall,
    func_csrrw,
    func_csrrs,
    func_csrrc,
    func_csrrwi,
    func_csrrsi,
    func_csrrci,
    func_flw,
    func_fsw,
    func_fmadd_s,
    func_fmsub_s,
    func_fnmsub_s,
    func_fnmadd_s,
    func_fadd_s,
    func_fsub_s,
    func_fmul_s,
    func_fdiv_s,
    func_fsqrt_s,
    func_fsgnj_s,
    func_fsgnjn_s,
    func_fsgnjx_s,
    func_fmin_s,
    func_fmax_s,
    func_fcvt_w_s,
    func_fcvt_wu_s,
    func_fmv_x_w,
    func_feq_s,
    func_flt_s,
    func_fle_s,
    func_fclass_s,
    func_fcvt_s_w,
    func_fcvt_s_wu,
    func_fmv_w_x,
    func_fcvt_l_s,
    func_fcvt_lu_s,
    func_fcvt_s_l,
    func_fcvt_s_lu,
    func_fld,
    func_fsd,
    func_fmadd_d,
    func_fmsub_d,
    func_fnmsub_d,
    func_fnmadd_d,
    func_fadd_d,
    func_fsub_d,
    func_fmul_d,
    func_fdiv_d,
    func_fsqrt_d,
    func_fsgnj_d,
    func_fsgnjn_d,
    func_fsgnjx_d,
    func_fmin_d,
    func_fmax_d,
    func_fcvt_s_d,
    func_fcvt_d_s,
    func_feq_d,
    func_flt_d,
    func_fle_d,
    func_fclass_d,
    func_fcvt_w_d,
    func_fcvt_wu_d,
    func_fcvt_d_w,
    func_fcvt_d_wu,
    func_fcvt_l_d,
    func_fcvt_lu_d,
    func_fmv_x_d,
    func_fcvt_d_l,
    func_fcvt_d_lu,
    func_fmv_d_x,
};


class interpreter
{
private:
    /* data */
public:
    decoder dc;
    CPU cpu;



    interpreter() {}
    ~interpreter() {}


    // void (interpreter::*inst_handle[INST_NUM])(CPU &host_cpu);

    // void set_inst_func(enum INST_NAME inst_name, void (interpreter::*fp)(CPU &host_cpu))
    // {
    //     inst_handle[inst_name] = fp;
    // }

    // void lui(CPU &host_cpu)
    // {
    //     printf("lui this->dc.imm= %llx\n", this->dc.imm);
    //     this->cpu.regs[this->dc.rd] = this->dc.imm<< 12;
    //     printf("lui this->dc.imm<< 12 = %llx\n", this->cpu.regs[this->dc.rd]);
    // }

    // void auipc(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.pc + (this->dc.imm<< 12);
    // }

    // void jal(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->dc.snpc;
    //     this->dc.dnpc = this->dc.imm+ this->cpu.pc;
    // }

    // void jalr(CPU &host_cpu)
    // {
    //     this->dc.dnpc = (this->cpu.regs[this->dc.rs1] + this->dc.imm) & ~1;
    //     this->cpu.regs[this->dc.rd] = this->dc.snpc;
    // }

    // void beq(CPU &host_cpu)
    // {
    //     if (this->cpu.regs[this->dc.rs1] == this->cpu.regs[this->dc.rs2])
    //     {
    //         printf("beq offset = 0x%lx\n", (unsigned long)this->dc.imm);
    //         this->dc.dnpc = this->cpu.pc + this->dc.imm;
    //     }
    // }

    // void bne(CPU &host_cpu)
    // {
    //     if (this->cpu.regs[this->dc.rs1] != this->cpu.regs[this->dc.rs2])
    //     {
    //         printf("bne offset = 0x%lx, rs1 = 0x%lx, rs2 = 0x%lx\n", (unsigned long)this->dc.imm, (unsigned long)this->cpu.regs[this->dc.rs1], (unsigned long)this->cpu.regs[this->dc.rs2]);
    //         this->dc.dnpc = this->cpu.pc + this->dc.imm;
    //     }
    // }

    // void blt(CPU &host_cpu)
    // {
    //     if ((long long)this->cpu.regs[this->dc.rs1] < (long long)this->cpu.regs[this->dc.rs2])
    //     {
    //         this->dc.dnpc = this->cpu.pc + this->dc.imm;
    //     }
    // }

    // void bge(CPU &host_cpu)
    // {
    //     if ((long long)this->cpu.regs[this->dc.rs1] >= (long long)this->cpu.regs[this->dc.rs2])
    //     {
    //         this->dc.dnpc = this->cpu.pc + this->dc.imm;
    //     }
    // }

    // void bltu(CPU &host_cpu)
    // {
    //     if (this->cpu.regs[this->dc.rs1] < this->cpu.regs[this->dc.rs2])
    //     {
    //         this->dc.dnpc = this->cpu.pc + this->dc.imm;
    //     }
    // }

    // void bgeu(CPU &host_cpu)
    // {
    //     if (this->cpu.regs[this->dc.rs1] >= this->cpu.regs[this->dc.rs2])
    //     {
    //         this->dc.dnpc = this->cpu.pc + this->dc.imm;
    //     }
    // }

    // void lb(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(this->cpu.cpu_load(this->cpu.regs[this->dc.rs1] + this->dc.imm, 1), 8);
    // }

    // void lh(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(this->cpu.cpu_load(this->cpu.regs[this->dc.rs1] + this->dc.imm, 2), 16);
    // }

    // void lw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(this->cpu.cpu_load(this->cpu.regs[this->dc.rs1] + this->dc.imm, 4), 32);
    // }

    // void lbu(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.cpu_load(this->cpu.regs[this->dc.rs1] + this->dc.imm, 1);
    // }

    // void lhu(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.cpu_load(this->cpu.regs[this->dc.rs1] + this->dc.imm, 2);
    // }

    // void lwu(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.cpu_load(this->cpu.regs[this->dc.rs1] + this->dc.imm, 4);
    // }

    // void ld(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.cpu_load(this->cpu.regs[this->dc.rs1] + this->dc.imm, 8);
    // }

    // void sb(CPU &host_cpu)
    // {
    //     this->cpu.cpu_store(this->cpu.regs[this->dc.rs1] + this->dc.imm, 1, this->cpu.regs[this->dc.rs2]);
    // }

    // void sh(CPU &host_cpu)
    // {
    //     this->cpu.cpu_store(this->cpu.regs[this->dc.rs1] + this->dc.imm, 2, this->cpu.regs[this->dc.rs2]);
    // }

    // void sw(CPU &host_cpu)
    // {
    //     this->cpu.cpu_store(this->cpu.regs[this->dc.rs1] + this->dc.imm, 4, this->cpu.regs[this->dc.rs2]);
    // }

    // void sd(CPU &host_cpu)
    // {
    //     printf("sd addr = 0x%llx\n", this->cpu.regs[this->dc.rs1] + this->dc.imm);
    //     this->cpu.cpu_store(this->cpu.regs[this->dc.rs1] + this->dc.imm, 8, this->cpu.regs[this->dc.rs2]);
    // }

    // void addi(CPU &host_cpu)
    // {
    //     printf("addi rd = %d x[rs1 = %d] = 0x%lx imm = 0x%lx\n", this->dc.rd, this->dc.rs1, (unsigned long)this->cpu.regs[this->dc.rs1], (unsigned long)this->dc.imm);
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] + this->dc.imm;
    // }

    // void slti(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = (long long)this->cpu.regs[this->dc.rs1] < (long long)this->dc.imm? 1 : 0;
    // }

    // void sltiu(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] < this->dc.imm? 1 : 0;
    // }

    // void xori(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] ^ this->dc.imm;
    // }

    // void ori(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] | this->dc.imm;
    // }

    // void andi(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] & this->dc.imm;
    // }

    // void slli(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] << this->dc.shamt;
    // }

    // void srli(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] >> this->dc.shamt;
    // }

    // void srai(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = ((long long)this->cpu.regs[this->dc.rs1]) >> this->dc.shamt;
    // }

    // void add(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] + this->cpu.regs[this->dc.rs2];
    // }

    // void sub(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] - this->cpu.regs[this->dc.rs2];
    // }

    // void sll(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] << BITS(this->cpu.regs[this->dc.rs2], 5, 0);
    // }

    // void slt(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = (long long)this->cpu.regs[this->dc.rs1] < (long long)this->cpu.regs[this->dc.rs2] ? 1 : 0;
    // }

    // void sltu(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] < this->cpu.regs[this->dc.rs2] ? 1 : 0;
    // }

    // void xor_f(CPU &host_cpu) 
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] ^ this->cpu.regs[this->dc.rs2];
    // }

    // void srl(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] >> BITS(this->cpu.regs[this->dc.rs2], 5, 0);
    // }

    // void sra(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = ((long long)this->cpu.regs[this->dc.rs1]) >> BITS(this->cpu.regs[this->dc.rs2], 5, 0);
    // }

    // void or_f(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] | this->cpu.regs[this->dc.rs2];
    // }

    // void and_f(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = this->cpu.regs[this->dc.rs1] & this->cpu.regs[this->dc.rs2];
    // }

    // void fence(CPU &host_cpu)
    // {
    //     // todo
    //     return;
    // }

    // void trap_handler(CPU host_cpu, enum TRAP traptype, bool isException, u64 cause, u64 tval)
    // {
    //     if (traptype == Fatal)
    //     {
    //         this->cpu.state = CPU::CPU_STOP;
    //         return;
    //     }
    //     enum CPU::CPU_PRI_LEVEL nxt_level = CPU::M;
    //     if (this->cpu.pri_level <= CPU::S)
    //     {
    //         if ((isException && (host_cpu.get_csr(medeleg) & (1 << cause))) || (!isException && (host_cpu.get_csr(mideleg) & (1 << cause))))
    //         {
    //             nxt_level = CPU::S;
    //         }
    //     }
    //     if (nxt_level == CPU::S)
    //     {
    //         host_cpu.set_xpp(CPU::S, cpu.pri_level);
    //         host_cpu.set_xpie(CPU::S, host_cpu.get_xie(CPU::S));
    //         host_cpu.set_xie(CPU::S, 0);
    //         host_cpu.set_csr(sepc, cpu.pc);
    //         host_cpu.set_csr(stval, tval);
    //         host_cpu.set_csr(scause, ((isException ? 0ull : 1ull) << 63) | cause);
    //         u64 tvec = host_cpu.get_csr(stvec);
    //         this->dc.dnpc = (BITS(tvec, 63, 2) << 2) + (BITS(tvec, 1, 0) == 1 ? cause * 4 : 0);
    //     }
    //     else
    //     {
    //         host_cpu.set_xpp(CPU::M, cpu.pri_level);
    //         host_cpu.set_xpie(CPU::M, host_cpu.get_xie(CPU::M));
    //         host_cpu.set_xie(CPU::M, 0);
    //         host_cpu.set_csr(mepc, cpu.pc);
    //         host_cpu.set_csr(mtval, tval);
    //         host_cpu.set_csr(mcause, ((isException ? 0ull : 1ull) << 63) | cause);
    //         u64 tvec = host_cpu.get_csr(mtvec);
    //         this->dc.dnpc = (BITS(tvec, 63, 2) << 2) + (BITS(tvec, 1, 0) == 1 ? cause * 4 : 0);
    //     }
    //     cpu.pri_level = nxt_level;
    // }

    // void ecall(CPU &host_cpu)
    // {
    //     if (this->dc.riscv_tests && this->cpu.regs[CPU::a7] == 93)
    //     {
    //         if (this->cpu.regs[CPU::a0] == 0)
    //         {
    //             printf("Test Pass\n");
    //             this->cpu.state = CPU::CPU_STOP;
    //         }
    //         else
    //         {
    //             printf("Test #%d Fail\n", (int)this->cpu.regs[CPU::a0] / 2);
    //             this->cpu.state = CPU::CPU_STOP;
    //         }
    //     }
    //     todo("trap_handler");
    //     trap_handler(host_cpu, Requested, false, this->cpu.pri_level + 8, 0);
    //     return;
    // }

    // void ebreak(CPU &host_cpu)
    // {
    //     // todo
    //     exit(0);
    //     return;
    // }

    // void addiw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(BITS(this->cpu.regs[this->dc.rs1] + this->dc.imm, 31, 0), 32);
    // }

    // void slliw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(BITS(this->cpu.regs[this->dc.rs1] << this->dc.shamt, 31, 0), 32);
    // }

    // void srliw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(BITS(this->cpu.regs[this->dc.rs1], 31, 0) >> this->dc.shamt, 32);
    // }

    // void sraiw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(((int)BITS(this->cpu.regs[this->dc.rs1], 31, 0)) >> this->dc.shamt, 32);
    // }

    // void addw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(BITS(this->cpu.regs[this->dc.rs1] + this->cpu.regs[this->dc.rs2], 31, 0), 32);
    // }

    // void subw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(this->cpu.regs[this->dc.rs1] - this->cpu.regs[this->dc.rs2], 32);
    // }

    // void sllw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(BITS(this->cpu.regs[this->dc.rs1] << BITS(this->cpu.regs[this->dc.rs2], 4, 0), 31, 0), 32);
    // }

    // void srlw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT(BITS(this->cpu.regs[this->dc.rs1], 31, 0) >> BITS(this->cpu.regs[this->dc.rs2], 4, 0), 32);
    // }

    // void sraw(CPU &host_cpu)
    // {
    //     this->cpu.regs[this->dc.rd] = SEXT((int)BITS(this->cpu.regs[this->dc.rs1], 31, 0) >> BITS(this->cpu.regs[this->dc.rs2], 4, 0), 32);
    // }

    // // Zicsr
    // void csrrw(CPU &host_cpu)
    // {
    //     u64 csrval;
    //     if (this->dc.rd != 0)
    //         csrval = this->cpu.csr.csr[this->dc.csr_addr];
    //     else
    //         csrval = 0;
    //     u64 rs1val = this->cpu.regs[this->dc.rs1];
    //     printf("csrval = 0x%08lx, rs1val = 0x%08lx\n", (unsigned long)csrval, (unsigned long)rs1val);
    //     this->cpu.regs[this->dc.rd] = csrval;
    //     this->cpu.csr.csr[this->dc.csr_addr] = rs1val;
    // }

    // void csrrs(CPU &host_cpu)
    // {
    //     u64 csrval = this->cpu.csr.csr[this->dc.csr_addr];
    //     u64 rs1val = this->dc.rs1 == 0 ? 0 : this->cpu.regs[this->dc.rs1];
    //     printf("before csrval = 0x%08lx, rs1val = 0x%08lx\n", (unsigned long)csrval, (unsigned long)rs1val);
    //     this->cpu.regs[this->dc.rd] = csrval;
    //     if (this->dc.rs1 != 0)
    //         this->cpu.csr.csr[this->dc.csr_addr] = csrval | rs1val;
    //     printf("after csrval = 0x%08lx, rs1val = 0x%08lx\n", (unsigned long)this->cpu.csr.csr[this->dc.csr_addr], (unsigned long)rs1val);
    // }

    // void csrrc(CPU &host_cpu)
    // {
    //     u64 csrval = this->cpu.csr.csr[this->dc.csr_addr];
    //     u64 rs1val = this->dc.rs1 == 0 ? 0 : this->cpu.regs[this->dc.rs1];
    //     this->cpu.regs[this->dc.rd] = csrval;
    //     rs1val = ~rs1val;
    //     if (this->dc.rs1 != 0)
    //         this->cpu.csr.csr[this->dc.csr_addr] = csrval & rs1val;
    // }

    // void csrrwi(CPU &host_cpu)
    // {
    //     u64 uimm = this->dc.rs1;
    //     u64 csrval = this->dc.rd == 0 ? 0 : this->cpu.csr.csr[this->dc.csr_addr];
    //     this->cpu.regs[this->dc.rd] = csrval;
    //     this->cpu.csr.csr[this->dc.csr_addr] = uimm;
    // }

    // void csrrsi(CPU &host_cpu)
    // {
    //     u64 uimm = this->dc.rs1;
    //     u64 csrval = this->cpu.csr.csr[this->dc.csr_addr];
    //     this->cpu.regs[this->dc.rd] = csrval;
    //     this->cpu.csr.csr[this->dc.csr_addr] = csrval | uimm;
    // }

    // void csrrci(CPU &host_cpu)
    // {
    //     u64 uimm = this->dc.rs1;
    //     u64 csrval = this->cpu.csr.csr[this->dc.csr_addr];
    //     this->cpu.regs[this->dc.rd] = csrval;
    //     uimm = ~uimm;
    //     this->cpu.csr.csr[this->dc.csr_addr] = csrval & uimm;
    // }

    // // trap return inst
    // void mret(CPU &host_cpu)
    // {
    //     int pre_level = host_cpu.get_xpp(CPU::M);
    //     host_cpu.set_xie(CPU::M, host_cpu.get_xpie(CPU::M));
    //     host_cpu.set_xpie(CPU::M, 1);
    //     host_cpu.set_xpp(CPU::M, CPU::U);
    //     host_cpu.set_csr(mstatus, host_cpu.get_csr(mstatus) & (~(1 << 17)));
    //     this->dc.dnpc = host_cpu.get_csr(mepc);
    //     this->cpu.pri_level = CPU::cast_to_pre_level(pre_level);
    // }

    // void sret(CPU &host_cpu)
    // {
    //     int pre_level = host_cpu.get_xpp(CPU::S);
    //     host_cpu.set_xie(CPU::S, host_cpu.get_xpie(CPU::S));
    //     host_cpu.set_xpie(CPU::S, 1);
    //     host_cpu.set_xpp(CPU::S, CPU::U);
    //     host_cpu.set_csr(sstatus, host_cpu.get_csr(sstatus) & (~(1 << 17)));
    //     this->dc.dnpc = host_cpu.get_csr(sepc);
    //     this->cpu.pri_level = CPU::cast_to_pre_level(pre_level);
    // }

    // void init_inst_func()
    // {
    //     set_inst_func(LUI, &interpreter::lui);
    //     set_inst_func(AUIPC, &interpreter::auipc);
    //     set_inst_func(JAL, &interpreter::jal);
    //     set_inst_func(JALR, &interpreter::jalr);
    //     set_inst_func(BEQ, &interpreter::beq);
    //     set_inst_func(BNE, &interpreter::bne);
    //     set_inst_func(BLT, &interpreter::blt);
    //     set_inst_func(BGE, &interpreter::bge);
    //     set_inst_func(BLTU, &interpreter::bltu);
    //     set_inst_func(BGEU, &interpreter::bgeu);
    //     set_inst_func(LB, &interpreter::lb);
    //     set_inst_func(LH, &interpreter::lh);
    //     set_inst_func(LW, &interpreter::lw);
    //     set_inst_func(LBU, &interpreter::lbu);
    //     set_inst_func(LHU, &interpreter::lhu);
    //     set_inst_func(SB, &interpreter::sb);
    //     set_inst_func(SH, &interpreter::sh);
    //     set_inst_func(SW, &interpreter::sw);
    //     set_inst_func(ADDI, &interpreter::addi);
    //     set_inst_func(SLTI, &interpreter::slti);
    //     set_inst_func(SLTIU, &interpreter::sltiu);
    //     set_inst_func(XORI, &interpreter::xori);
    //     set_inst_func(ORI, &interpreter::ori);
    //     set_inst_func(ANDI, &interpreter::andi);
    //     set_inst_func(SLLI, &interpreter::slli);
    //     set_inst_func(SRLI, &interpreter::srli);
    //     set_inst_func(SRAI, &interpreter::srai);
    //     set_inst_func(ADD, &interpreter::add);
    //     set_inst_func(SUB, &interpreter::sub);
    //     set_inst_func(SLL, &interpreter::sll);
    //     set_inst_func(SLT, &interpreter::slt);
    //     set_inst_func(SLTU, &interpreter::sltu);
    //     set_inst_func(XOR, &interpreter::xor_f);
    //     set_inst_func(SRL, &interpreter::srl);
    //     set_inst_func(SRA, &interpreter::sra);
    //     set_inst_func(OR, &interpreter::or_f);
    //     set_inst_func(AND, &interpreter::and_f);
    //     set_inst_func(FENCE, &interpreter::fence);
    //     set_inst_func(ECALL, &interpreter::ecall);
    //     set_inst_func(EBREAK, &interpreter::ebreak);
    //     set_inst_func(LWU, &interpreter::lwu);
    //     set_inst_func(LD, &interpreter::ld);
    //     set_inst_func(SD, &interpreter::sd);
    //     set_inst_func(ADDIW, &interpreter::addiw);
    //     set_inst_func(SLLIW, &interpreter::slliw);
    //     set_inst_func(SRLIW, &interpreter::srliw);
    //     set_inst_func(SRAIW, &interpreter::sraiw);
    //     set_inst_func(ADDW, &interpreter::addw);
    //     set_inst_func(SUBW, &interpreter::subw);
    //     set_inst_func(SLLW, &interpreter::sllw);
    //     set_inst_func(SRLW, &interpreter::srlw);
    //     set_inst_func(SRAW, &interpreter::sraw);

    //     // Zicsr
    //     set_inst_func(CSRRW, &interpreter::csrrw);
    //     set_inst_func(CSRRS, &interpreter::csrrs);
    //     set_inst_func(CSRRC, &interpreter::csrrc);
    //     set_inst_func(CSRRWI, &interpreter::csrrwi);
    //     set_inst_func(CSRRSI, &interpreter::csrrsi);
    //     set_inst_func(CSRRCI, &interpreter::csrrci);

    //     // mret & sret
    //     set_inst_func(MRET, &interpreter::mret);
    //     set_inst_func(SRET, &interpreter::sret);
    // }

    // void interp_exec_inst(CPU &host_cpu)
    // {
    //     (this->*inst_handle[this->dc.inst_name])(host_cpu);
    // }

// ============================================================================== //
// version 2.0
// ============================================================================== //






void exec_block_interp(CPU &host_cpu)
{
    static insn_t insn = {0};
    while (true)
    { // 内存循环
        u32 data = *(u32 *)TO_HOST(host_cpu.pc);
        this->dc.insn_decode(&insn, data); // 指令解码
        funcs[insn.type](host_cpu, &insn); // 匹配执行
        // zero寄存器清零
        host_cpu.regs[zero] = 0;
        // 如果指令继续执行，则跳出循环
        if (insn.cont)
                break;
        // 如果为压缩指令步进2，否则步进4
        host_cpu.pc += insn.rvc ? 2 : 4;
    }
}


};





#endif // EMULATOR_INTERPRETER_HPP