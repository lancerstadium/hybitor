/*
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-10 16:28:11
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-11 12:02:41
 * @FilePath: /hybitor_effect/subitem/hyarmdec/hyarmdec.h
 * @Description: ARM64 指令相关定义
 */

#ifndef HYARMDEC_H
#define HYARMDEC_H

#include <stdint.h>

/// ==== 类型定义 ==== ///
#ifdef HYARMDEC_INTERNAL
typedef unsigned int uint;
typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;
typedef float    f32;
typedef double   f64;
#else
#define uint unsigned int
#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define i8 int8_t
#define i16 int16_t
#define i32 int32_t
#define i64 int64_t
#define f32 float
#define f64 double
#endif  // HYARMDEC_INTERNAL


#ifndef __cplusplus // C 版本
typedef enum Opcode Opcode;
typedef enum AddrMode AddrMode;
typedef enum Cond Cond;
typedef enum ExtendType ExtendType;
typedef enum FPSize FPSize;
typedef enum MemOrdering MemOrdering;
typedef enum PstateField PstateField; // for MSR_IMM
typedef enum Shift Shift;
typedef enum Size Size;
typedef enum VectorArrangement VectorArrangement;
typedef struct Inst Inst;
#else   // C++ 版本
namespace hyarmdec {    // namespace hyarmdec
#endif





/// @brief 寄存器
typedef u8 Reg;

/// @brief 操作码
enum Opcode {
    ARM64_UNKNOWN, // 未知指令 (or Opcode field not set, by accident), Inst.imm contains raw binary instruction
	ARM64_ERROR,   // 非法指令, Inst.error contains error string
	ARM64_UDF,     // 抛出未找到指令异常

	/*** Data Processing -- Immediate ***/

	// PC-rel. addressing
	ARM64_ADR,     // ADR Xd, label  -- Xd ← PC + label
	ARM64_ADRP,    // ADRP Xd, label -- Xd ← PC + (label * 4K)

	// Add/subtract (immediate, with tags) -- OMITTED

	// Add/subtract (immediate)
	ARM64_ADD_IMM,
	ARM64_CMN_IMM,
	ARM64_MOV_SP, // MOV from/to SP -- ADD (imm) alias (predicate: shift == 0 && imm12 == 0 && (Rd == SP || Rn == SP))
	ARM64_SUB_IMM,
	ARM64_CMP_IMM,

	// Logical (immediate)
	ARM64_AND_IMM,
	ARM64_ORR_IMM,
	ARM64_EOR_IMM,
	ARM64_TST_IMM, // TST Rn -- ANDS alias (Rd := RZR, predicate: Rd == ZR && set_flags)

	// Move wide (immediate)
	ARM64_MOVK, // keep other bits

	// Synthetic instruction comprising MOV (bitmask immediate), MOV (inverted wide immediate)
	// and MOV (wide immediate), MOVN and MOVZ; essentially all MOVs where the result of the
	// operation can be precalculated. For lifting, we do not care how the immediate was encoded,
	// only that it is an immediate move.
	ARM64_MOV_IMM,

	// Bitfield
	ARM64_SBFM,    // always decoded to an alias
	ARM64_ASR_IMM,
	ARM64_SBFIZ,
	ARM64_SBFX,
	ARM64_BFM,     // always decoded to an alias
	ARM64_BFC,
	ARM64_BFI,
	ARM64_BFXIL,
	ARM64_UBFM,    // always decoded to an alias
	ARM64_LSL_IMM,
	ARM64_LSR_IMM,
	ARM64_UBFIZ,
	ARM64_UBFX,

	// Synthetic instruction comprising the SXTB, SXTH, SXTW, UXTB and UXTH aliases of SBFM and UBFM.
	// The kind of extension is stored in Inst.extend.type.
	ARM64_EXTEND,

	// Extract
	ARM64_EXTR,
	ARM64_ROR_IMM, // ROR Rd, Rs, #shift -- EXTR alias (Rm := Rs, Rn := Rs, predicate: Rm == Rn)

	/*** Branches, Exception Generating and System Instructions ***/

	ARM64_BCOND,

	// Exception generation
	//
	// With the exception of SVC, they are not interesting for lifting
	// userspace programs, but were included since they are trivial.
	ARM64_SVC, // system call
	ARM64_HVC,
	ARM64_SMC,
	ARM64_BRK,
	ARM64_HLT,
	ARM64_DCPS1,
	ARM64_DCPS2,
	ARM64_DCPS3,

	// Hints -- we treat all allocated hints as NOP and don't decode to the "aliases"
	// NOP, YIELD, ...
	ARM64_HINT, 

	// Barriers
	ARM64_CLREX,   
	ARM64_DMB,
	ARM64_ISB,
	ARM64_SB,
	ARM64_DSB,
	ARM64_SSBB,
	ARM64_PSSBB,

	// PSTATE
	ARM64_MSR_IMM, // MSR <pstatefield>, #imm -- Inst.msr_imm
	ARM64_CFINV,
	ARM64_XAFlag,  // irrelevant
	ARM64_AXFlag,  // ------

	// 系统指令 -- Inst.ldst.rt := Xt
	ARM64_SYS,  // SYS #op1, Cn, Cm, #op2(, Xt)
	ARM64_SYSL, // SYSL Xt, #op1, Cn, Cm, #op2

	// 系统寄存器移动 -- Inst.ldst.rt := Xt; Inst.imm := sysreg
	ARM64_MSR_REG, // MSR <sysreg>, Xt
	ARM64_MRS,     // MRS Xt, <sysreg>

	// 无条件分支（寄存器）
	ARM64_BR,
	ARM64_BLR,
	ARM64_RET,

	// 无条件分支（立即数）
	ARM64_B,
	ARM64_BL,

	// Compare and branch (immediate)
	ARM64_CBZ,
	ARM64_CBNZ,

	// Test and branch (immediate) -- Inst.tbz
	ARM64_TBZ,
	ARM64_TBNZ,

	/*** Data Processing -- Register ***/

	// Data-processing (2 source)
	ARM64_UDIV,
	ARM64_SDIV,
	ARM64_LSLV,
	ARM64_LSRV,
	ARM64_ASRV,
	ARM64_RORV,
	ARM64_CRC32B,
	ARM64_CRC32H,
	ARM64_CRC32W,
	ARM64_CRC32X,
	ARM64_CRC32CB,
	ARM64_CRC32CH,
	ARM64_CRC32CW,
	ARM64_CRC32CX,
	ARM64_SUBP,

	// Data-processing (1 source)
	ARM64_RBIT,
	ARM64_REV16,
	ARM64_REV,
	ARM64_REV32,
	ARM64_CLZ,
	ARM64_CLS,

	// 逻辑 (移位寄存器)
	ARM64_AND_SHIFTED,  
	ARM64_TST_SHIFTED, // ANDS alias (Rd := ZR, predicate: Rd == ZR)
	ARM64_BIC,         
	ARM64_ORR_SHIFTED,
	ARM64_MOV_REG,     // ORR alias (predicate: shift == 0 && imm6 == 0 && Rn == ZR)
	ARM64_ORN,
	ARM64_MVN,         // ORN alias (Rn := ZR, predicate: Rn == ZR)
	ARM64_EOR_SHIFTED,
	ARM64_EON,

	// Add/subtract (shifted register)
	ARM64_ADD_SHIFTED,
	ARM64_CMN_SHIFTED, // ADDS alias (Rd := ZR, predicate: Rd == ZR && set_flags)
	ARM64_SUB_SHIFTED,
	ARM64_NEG,         // SUB alias (Rn := ZR, predicate: Rn == ZR)
	ARM64_CMP_SHIFTED, // SUBS alias (Rd := ZR, predicate: Rd == ZR && set_flags)

	// Add/subtract (extended register)
	// Register 31 is interpreted as the stack pointer (SP/WSP).
	ARM64_ADD_EXT,
	ARM64_CMN_EXT, // ADDS alias (Rd := ZR, predicate: Rd == ZR && set_flags)
	ARM64_SUB_EXT,
	ARM64_CMP_EXT, // SUBS alias (Rd := ZR, predicate: Rd == ZR && set_flags)

	// Add/subtract (with carry)
	ARM64_ADC,
	ARM64_SBC,
	ARM64_NGC, // SBC alias (Rd := ZR, predicate: Rd == RR)

	// Rotate right into flags
	ARM64_RMIF,

	// Evaluate into flags
	ARM64_SETF8,
	ARM64_SETF16,

	// Conditional compare (register)
	ARM64_CCMN_REG,
	ARM64_CCMP_REG,

	// Conditional compare (immediate)
	ARM64_CCMN_IMM,
	ARM64_CCMP_IMM,

	// Conditional select
	ARM64_CSEL,
	ARM64_CSINC,
	ARM64_CINC,  // CSINC alias (cond := invert(cond), predicate: Rm == Rn != ZR)
	ARM64_CSET,  // CSINC alias (cond := invert(cond), predicate: Rm == Rn == ZR)
	ARM64_CSINV,
	ARM64_CINV,  // CSINV alias (cond := invert(cond), predicate: Rm == Rn != ZR)
	ARM64_CSETM, // CSINV alias (cond := invert(cond), predicate: Rm == Rn == ZR)
	ARM64_CSNEG,
	ARM64_CNEG,  // CSNEG alias (cond := invert(cond), predicate: Rm == Rn)

	// Data-processing (3 source)
	ARM64_MADD,
	ARM64_MUL,    // MADD alias (Ra omitted, predicate: Ra == ZR)
	ARM64_MSUB,
	ARM64_MNEG,   // MSUB alias (^---- see above)
	ARM64_SMADDL,
	ARM64_SMULL,  // SMADDL alias  (^---- see above)
	ARM64_SMSUBL,
	ARM64_SMNEGL, // SMSUBL alias (^---- see above)
	ARM64_SMULH,
	ARM64_UMADDL,
	ARM64_UMULL,  // UMADDL alias (^---- see above)
	ARM64_UMSUBL,
	ARM64_UMNEGL, // UMSUBL alias (^---- see above)
	ARM64_UMULH,

	/*** Loads and Stores ***/

	// There are not that many opcodes because access size, sign-extension
	// and addressing mode (post-indexed, register offset, immediate) are
	// encoded in the Inst, to leverage the regular structure and cut down
	// on opcodes (and by extension, duplicative switch-cases for the user
	// of this decoder).

	// Advanced SIMD load/store multiple structures
	// Advanced SIMD load/store multiple structures (post-indexed)
	ARM64_LD1_MULT,
	ARM64_ST1_MULT,
	ARM64_LD2_MULT,
	ARM64_ST2_MULT,
	ARM64_LD3_MULT,
	ARM64_ST3_MULT,
	ARM64_LD4_MULT,
	ARM64_ST4_MULT,

	// Advanced SIMD load/store single structure
	// Advanced SIMD load/store single structure (post-indexed)
	ARM64_LD1_SINGLE,
	ARM64_ST1_SINGLE,
	ARM64_LD2_SINGLE,
	ARM64_ST2_SINGLE,
	ARM64_LD3_SINGLE,
	ARM64_ST3_SINGLE,
	ARM64_LD4_SINGLE,
	ARM64_ST4_SINGLE,
	ARM64_LD1R,
	ARM64_LD2R,
	ARM64_LD3R,
	ARM64_LD4R,

	// Load/store exclusive
	ARM64_LDXR,  // includes Load-acquire variants
	ARM64_STXR,  // includes Store-acquire variants (STLXR)
	ARM64_LDXP,  // ------
	ARM64_STXP,  // ------
	ARM64_LDAPR, // Load-AcquirePC Register (actually in Atomic group)

	// Load/store no-allocate pair (offset)
	ARM64_LDNP,
	ARM64_STNP,
	ARM64_LDNP_FP,
	ARM64_STNP_FP,

	// Load-acquire/store-release register     -- AM_SIMPLE
	// Load/store register pair (post-indexed) -- AM_POST
	// Load/store register pair (offset)       -- AM_OFF_IMM
	// Load/store register pair (pre-indexed)  -- AM_PRE
	ARM64_LDP, // LDP, LDXP
	ARM64_STP, // STP, STXP
	ARM64_LDP_FP,
	ARM64_STP_FP,

	// Load/store register (unprivileged): unsupported system instructions

	// Load register (literal)                      -- AM_LITERAL
	// Load-acquire/store-release register          -- AM_SIMPLE
	// Load-LOAcquire/Store-LORelease register      -- AM_SIMPLE
	// Load/store register (immediate post-indexed) -- AM_POST
	// Load/store register (immediate pre-indexed)  -- AM_PRE
	// Load/store register (register offset)        -- AM_OFF_REG, AM_OFF_EXT
	// Load/store register (unsigned immediate)     -- AM_OFF_IMM
	// Load/store register (unscaled immediate)     -- AM_OFF_IMM
	ARM64_LDR, // LDR, LDAR, LDLAR, LDUR
	ARM64_STR, // STR, STLR, STLLR, STUR
	ARM64_LDR_FP,
	ARM64_STR_FP,

	// Prefetch memory
	//
	// The exact prefetch operation is stored in Inst.rt := Rt.
	// We cannot use a "struct prfm" because the addressing mode-specific
	// data (offset, .extend) already occupies the space.
	//
	// PRFM (literal)          -- AM_LITERAL
	// PRFM (register)         -- AM_OFF_EXT
	// PRFM (immediate)        -- AM_OFF_IMM
	// PRFUM (unscaled offset) -- AM_OFF_IMM
	ARM64_PRFM,

	// Atomic memory operations
	//
	// Whether the instruction has load-acquire (e.g. LDADDA*), load-acquire/
	// store-release (e.g. LDADDAL*) or store-release (e.g. STADDL) semantics
	// is stored in ldst_order.load and .store.
	//
	// There are no ST* aliases; the only difference to the LD* instructions
	// is that the original value of the memory cell is discarded by writing
	// to the zero register.
	ARM64_LDADD,
	ARM64_LDCLR,
	ARM64_LDEOR,
	ARM64_LDSET,
	ARM64_LDSMAX,
	ARM64_LDSMIN,
	ARM64_LDUMAX,
	ARM64_LDUMIN,
	ARM64_SWP,
	ARM64_CAS,   // Compare and Swap (actually from Exclusive group)
	ARM64_CASP,  // Compare and Swap Pair of (double)words (actually from Exclusive group)

	/*** Data Processing -- Scalar Floating-Point and Advanced SIMD ***/

	// The instructions are ordered by functionality here, because the order of the
	// top-level encodings, as used in the other categories, splits variants of the
	// same instruction. We want as few opcodes as possible.

	// Conversion between Floating Point and Integer/Fixed-Point
	//
	// Sca: SIMD&FP register interpreted as a scalar (Hn, Sn, Dn).
	// Vec: SIMD&FP register interpreted as a vector (Vn.<T>).
	// GPR: General Purpose Register (Wn, Xn).
	//
	// Inst.flags.W32  := GPR bits == 32
	// Inst.flags.prec := Sca(fp) precision (FPSize)
	// Inst.flags.ext  := Vec(fp) vector arrangement
	// Inst.fcvt.mode  := rounding mode
	// Inst.fcvt.fbits := #fbits for fixed-point
	// Inst.fcvt.typ   := signed OR unsigned OR fixed-point
	ARM64_FCVT_GPR, // Sca(fp)        → GPR(int|fixed)
	ARM64_FCVT_VEC, // Vec(fp)        → Vec(int|fixed)
	ARM64_CVTF,     // GPR(int|fixed) → Sca(fp)
	ARM64_CVTF_VEC, // Vec(int|fixed) → Vec(fp)
	ARM64_FJCVTZS,  // Sca(f32)       → GPR(i32); special Javascript instruction

	// Rounding and Precision Conversion
	//
	// Inst.flags.prec := Sca(fp) precision
	// Inst.frint.mode := rounding mode
	// Inst.frint.bits := 0 if any size, 32, 64
	ARM64_FRINT,   // Round to integral (any size, 32-bit, or 64-bit)
	ARM64_FRINT_VEC,
	ARM64_FRINTX,  // ---- Exact (throws Inexact exception on failure)
	ARM64_FRINTX_VEC,
	ARM64_FCVT_H,  // Convert from any precision to Half
	ARM64_FCVT_S,  // -------------------------- to Single
	ARM64_FCVT_D,  // -------------------------- to Double
	ARM64_FCVTL,   // Extend to higher precision (vector)
	ARM64_FCVTN,   // Narrow to lower precision  (vector)
	ARM64_FCVTXN,  // Narrow to lower precision, round to odd (vector)

	// Floating-Point Computation (scalar)
	ARM64_FABS, 
	ARM64_FNEG,
	ARM64_FSQRT,
	ARM64_FMUL,
	ARM64_FMULX,
	ARM64_FDIV,
	ARM64_FADD,
	ARM64_FSUB,
	ARM64_FMAX,   // max(n, NaN) → exception or FPSR flag set
	ARM64_FMAXNM, // max(n, NaN) → n
	ARM64_FMIN,   // min(n, NaN) → exception or FPSR flag set
	ARM64_FMINNM, // min(n, NaN) → n

	// Floating-Point Stepwise (scalar)
	ARM64_FRECPE,
	ARM64_FRECPS,
	ARM64_FRECPX,
	ARM64_FRSQRTE,
	ARM64_FRSQRTS,

	// Floating-Point Fused Multiply (scalar)
	ARM64_FNMUL,
	ARM64_FMADD, 
	ARM64_FMSUB,
	ARM64_FNMADD,
	ARM64_FNMSUB,

	// Floating-Point Compare, Select, Move (scalar)
	ARM64_FCMP_REG,   // compare Rn, Rm
	ARM64_FCMP_ZERO,  // compare Rn and 0.0
	ARM64_FCMPE_REG,
	ARM64_FCMPE_ZERO,
	ARM64_FCCMP,
	ARM64_FCCMPE,
	ARM64_FCSEL,
	ARM64_FMOV_VEC2GPR, // GPR ← SIMD&FP reg, without conversion
	ARM64_FMOV_GPR2VEC, // GPR → SIMD&FP reg, ----
	ARM64_FMOV_TOP2GPR, // GPR ← SIMD&FP top half (of full 128 bits), ----
	ARM64_FMOV_GPR2TOP, // GPR → SIMD&FP top half (of full 128 bits), ----
	ARM64_FMOV_REG, // SIMD&FP ←→ SIMD&FP
	ARM64_FMOV_IMM, // SIMD&FP ← 8-bit float immediate (see VFPExpandImm)
	ARM64_FMOV_VEC, // vector ← 8-bit imm ----; replicate imm to all lanes

	// SIMD Floating-Point Compare
	ARM64_FCMEQ_REG,
	ARM64_FCMEQ_ZERO,
	ARM64_FCMGE_REG,
	ARM64_FCMGE_ZERO,
	ARM64_FCMGT_REG,
	ARM64_FCMGT_ZERO,
	ARM64_FCMLE_ZERO,
	ARM64_FCMLT_ZERO,
	ARM64_FACGE,
	ARM64_FACGT,

	// SIMD Simple Floating-Point Computation (vector <op> vector, vector <op> vector[i])
	ARM64_FABS_VEC,
	ARM64_FABD_VEC,
	ARM64_FNEG_VEC,
	ARM64_FSQRT_VEC,
	ARM64_FMUL_ELEM,
	ARM64_FMUL_VEC,
	ARM64_FMULX_ELEM,
	ARM64_FMULX_VEC,
	ARM64_FDIV_VEC,
	ARM64_FADD_VEC,
	ARM64_FCADD, // complex addition; Inst.imm := rotation in degrees (90, 270)
	ARM64_FSUB_VEC,
	ARM64_FMAX_VEC,
	ARM64_FMAXNM_VEC,
	ARM64_FMIN_VEC,
	ARM64_FMINNM_VEC,

	// SIMD Floating-Point Stepwise
	ARM64_FRECPE_VEC,
	ARM64_FRECPS_VEC,
	ARM64_FRSQRTE_VEC,
	ARM64_FRSQRTS_VEC,

	// SIMD Floating-Point Fused Multiply
	ARM64_FMLA_ELEM,
	ARM64_FMLA_VEC,
	ARM64_FMLAL_ELEM,
	ARM64_FMLAL_VEC,
	ARM64_FMLAL2_ELEM,
	ARM64_FMLAL2_VEC,
	ARM64_FCMLA_ELEM, // Inst.imm := rotation in degrees (0, 90, 180, 270)
	ARM64_FCMLA_VEC,  // ---
	ARM64_FMLS_ELEM,
	ARM64_FMLS_VEC,
	ARM64_FMLSL_ELEM,
	ARM64_FMLSL_VEC,
	ARM64_FMLSL2_ELEM,
	ARM64_FMLSL2_VEC,

	// SIMD Floating-Point Computation (reduce)
	ARM64_FADDP,
	ARM64_FADDP_VEC,
	ARM64_FMAXP,
	ARM64_FMAXP_VEC,
	ARM64_FMAXV,
	ARM64_FMAXNMP,
	ARM64_FMAXNMP_VEC,
	ARM64_FMAXNMV,
	ARM64_FMINP,
	ARM64_FMINP_VEC,
	ARM64_FMINV,
	ARM64_FMINNMP,
	ARM64_FMINNMP_VEC,
	ARM64_FMINNMV,

	// SIMD Bitwise: Logical, Pop Count, Bit Reversal, Byte Swap, Shifts
	ARM64_AND_VEC,
	ARM64_BCAX, // ARMv8.2-SHA
	ARM64_BIC_VEC_IMM,
	ARM64_BIC_VEC_REG,
	ARM64_BIF,
	ARM64_BIT,
	ARM64_BSL,
	ARM64_CLS_VEC,
	ARM64_CLZ_VEC,
	ARM64_CNT,
	ARM64_EOR_VEC,
	ARM64_EOR3,    // ARMv8.2-SHA
	ARM64_NOT_VEC, // also called MVN
	ARM64_ORN_VEC,
	ARM64_ORR_VEC_IMM,
	ARM64_ORR_VEC_REG,
	ARM64_MOV_VEC, // alias of ORR_VEC_REG
	ARM64_RAX1, // ARMv8.2-SHA
	ARM64_RBIT_VEC,
	ARM64_REV16_VEC,
	ARM64_REV32_VEC,
	ARM64_REV64_VEC,
	ARM64_SHL_IMM,
	ARM64_SHL_REG, // SSHL, USHL, SRSHL, URSHL
	ARM64_SHLL,    // SSHLL, USSHL
	ARM64_SHR,     // SSHR, USHR, SRSHR, URSHR
	ARM64_SHRN,    // SHRN, RSHRN
	ARM64_SRA,     // SSRA, USRA, SRSRA, URSRA
	ARM64_SLI,
	ARM64_SRI,
	ARM64_XAR, // ARMv8.2-SHA

	// SIMD Copy, Table Lookup, Transpose, Extract, Insert, Zip, Unzip
	//
	// Inst.imm := index i
	ARM64_DUP_ELEM, // ∀k < lanes: Dst[k] ← Src[i] (or if Dst is scalar: Dst ← Src[i])
	ARM64_DUP_GPR,  // ∀k < lanes: Dst[k] ← Xn
	ARM64_EXT,
	ARM64_INS_ELEM, // Dst[j] ← Src[i], (i, j stored in Inst.ins_elem)
	ARM64_INS_GPR,  // Dst[i] ← Xn
	ARM64_MOVI,     // includes MVNI
	ARM64_SMOV,     // Xd ← sext(Src[i])
	ARM64_UMOV,     // Xd ← Src[i]
	ARM64_TBL,      // Inst.imm := #regs of table ∈ {1,2,3,4}
	ARM64_TBX,      // ---
	ARM64_TRN1,
	ARM64_TRN2,
	ARM64_UZP1,
	ARM64_UZP2,
	ARM64_XTN,
	ARM64_ZIP1,
	ARM64_ZIP2,

	// SIMD Integer/Bitwise Compare
	ARM64_CMEQ_REG,
	ARM64_CMEQ_ZERO,
	ARM64_CMGE_REG,
	ARM64_CMGE_ZERO,
	ARM64_CMGT_REG,
	ARM64_CMGT_ZERO,
	ARM64_CMHI_REG,  // no ZERO variant
	ARM64_CMHS_REG,  // no ZERO variant
	ARM64_CMLE_ZERO, // no REG variant
	ARM64_CMLT_ZERO, // no REG variant
	ARM64_CMTST,

	// SIMD Integer Computation (vector <op> vector, vector <op> vector[i])
	//
	// Signedness (e.g. SABD vs UABD) is encoded via the SIMD_SIGNED flag,
	// rounding vs truncating behaviour (e.g. SRSHL vs SSHL) in SIMD_ROUND.
	ARM64_ABS_VEC,

	ARM64_ABD,
	ARM64_ABDL,
	ARM64_ABA,
	ARM64_ABAL,

	ARM64_NEG_VEC,

	ARM64_MUL_ELEM,
	ARM64_MUL_VEC,
	ARM64_MULL_ELEM,
	ARM64_MULL_VEC,

	ARM64_ADD_VEC,
	ARM64_ADDHN,
	ARM64_ADDL,
	ARM64_ADDW,
	ARM64_HADD,

	ARM64_SUB_VEC,
	ARM64_SUBHN,
	ARM64_SUBL,
	ARM64_SUBW,
	ARM64_HSUB,

	ARM64_MAX_VEC,
	ARM64_MIN_VEC,

	ARM64_DOT_ELEM,
	ARM64_DOT_VEC, // Inst.flags.vec = arrangement of destination (2s, 4s); sources are (8b, 16b)

	// SIMD Integer Stepwise (both are unsigned exclusive)
	ARM64_URECPE,
	ARM64_URSQRTE,

	// SIMD Integer Fused Multiply
	ARM64_MLA_ELEM,
	ARM64_MLA_VEC,
	ARM64_MLS_ELEM,
	ARM64_MLS_VEC,
	ARM64_MLAL_ELEM, // SMLAL, UMLAL
	ARM64_MLAL_VEC,  // SMLAL, UMLAL
	ARM64_MLSL_ELEM, // SMLSL, UMLSL
	ARM64_MLSL_VEC,  // SMLSL, UMLSL

	// SIMD Integer Computation (reduce)
	ARM64_ADDP,     // Scalar; Dd ← Vn.d[1] + Vn.d[0]
	ARM64_ADDP_VEC, // Concatenate Vn:Vm, then add pairwise and store result in Vd
	ARM64_ADDV,
	ARM64_ADALP,
	ARM64_ADDLP,
	ARM64_ADDLV,
	ARM64_MAXP,
	ARM64_MAXV,
	ARM64_MINP,
	ARM64_MINV,

	// SIMD Saturating Integer Arithmetic (unsigned, signed)
	ARM64_QADD,
	ARM64_QABS,
	ARM64_SUQADD,
	ARM64_USQADD,
	ARM64_QSHL_IMM,
	ARM64_QSHL_REG,
	ARM64_QSHRN,
	ARM64_QSUB,
	ARM64_QXTN,

	// SIMD Saturating Integer Arithmetic (signed exclusive)
	ARM64_SQABS,
	ARM64_SQADD,

	ARM64_SQDMLAL_ELEM,
	ARM64_SQDMLAL_VEC,
	ARM64_SQDMLSL_ELEM,
	ARM64_SQDMLSL_VEC,

	ARM64_SQDMULH_ELEM, // SQDMULH, SQRDMULH
	ARM64_SQDMULH_VEC,  // SQDMULH, SQRDMULH
	ARM64_SQDMULL_ELEM, // SQDMULL, SQRDMULL
	ARM64_SQDMULL_VEC,  // SQDMULL, SQRDMULL

	ARM64_SQNEG,

	// Only these rounded variations exist
	ARM64_SQRDMLAH_ELEM,
	ARM64_SQRDMLAH_VEC,	
	ARM64_SQRDMLSH_ELEM,
	ARM64_SQRDMLSH_VEC,

	ARM64_SQSHLU,
	ARM64_SQSHRUN, // SQSHRUN, SQRSHRUN
	ARM64_SQXTUN,

	// SIMD Polynomial Multiply
	ARM64_PMUL,
	ARM64_PMULL,
};


/// @brief 地址模式
enum AddrMode {
	AM_SIMPLE,  // [base] -- used by atomics, exclusive, ordered load/stores → check Inst.ldst_order
	AM_OFF_IMM, // [base, #imm]
	AM_OFF_REG, // [base, Xm, {LSL #imm}] (#imm either #log2(size) or #0)
	AM_OFF_EXT, // [base, Wm, {S|U}XTW {#imm}] (#imm either #log2(size) or #0)
	AM_PRE,     // [base, #imm]!
	AM_POST,    // [base],#imm  (for LDx, STx also register: [base],Xm)
	AM_LITERAL  // label
};

/// @brief 条件
enum Cond {
	COND_EQ = 0b0000,  // =
	COND_NE = 0b0001,  // ≠
	COND_CS = 0b0010,  // Carry Set
	COND_HS = COND_CS, // ≥, Unsigned
	COND_CC = 0b0011,  // Carry Clear
	COND_LO = COND_CC, // <, Unsigned
	COND_MI = 0b0100,  // < 0 (MInus)
	COND_PL = 0b0101,  // ≥ 0 (PLus)
	COND_VS = 0b0110,  // Signed Overflow
	COND_VC = 0b0111,  // No Signed Overflow
	COND_HI = 0b1000,  // >, Unsigned
	COND_LS = 0b1001,  // ≤, Unsigned
	COND_GE = 0b1010,  // ≥, Signed
	COND_LT = 0b1011,  // <, Signed
	COND_GT = 0b1100,  // >, Signed
	COND_LE = 0b1101,  // ≤, Signed
	COND_AL = 0b1110,  // Always true
	COND_NV = 0b1111,  // Always true (not "never" as in A32!)
};

/// @brief 偏移
enum Shift {
	SH_LSL = 0b00, // Logical Shift Left
	SH_LSR = 0b01, // Logical Shift Right
	SH_ASR = 0b10, // Arithmetic Shift Right
	SH_ROR = 0b11, // only for RORV instruction; shifted add/sub does not support it
	SH_RESERVED = SH_ROR
};

/// @brief 内存访问顺序
enum MemOrdering {
	MO_NONE,
	MO_ACQUIRE,    // Load-Acquire -- sequentially consistent Acquire
	MO_LO_ACQUIRE, // Load-LOAcquire -- Acquire in Limited Ordering Region (LORegion)
	MO_ACQUIRE_PC, // Load-AcquirePC -- weaker processor consistent (PC) Acquire
	MO_RELEASE,    // Store-Release
	MO_LO_RELEASE, // Store-LORelease -- Release in LORegion
};


/// @brief 数据大小
enum Size {
	SZ_B = 0b00, // Byte     -  8 bit
	SZ_H = 0b01, // Halfword - 16 bit
	SZ_W = 0b10, // Word     - 32 bit
	SZ_X = 0b11, // Extended - 64 bit
};

/// @brief 浮点数据大小
enum FPSize {
	FSZ_B = SZ_B, // Byte   -   8 bits
	FSZ_H = SZ_H, // Half   -  16 bits
	FSZ_S = SZ_W, // Single -  32 bits
	FSZ_D = SZ_X, // Double -  64 bits

	// "Virtual" encoding, never used in the actual instructions.
	// There, Quad precision is encoded in various incoherent ways.
	FSZ_Q = 0b111 // Quad   - 128 bits
};


/// @brief 向量数据大小
enum VectorArrangement {
	VA_8B  = (FSZ_B << 1) | 0, //  64 bit
	VA_16B = (FSZ_B << 1) | 1, // 128 bit
	VA_4H  = (FSZ_H << 1) | 0, //  64 bit
	VA_8H  = (FSZ_H << 1) | 1, // 128 bit
	VA_2S  = (FSZ_S << 1) | 0, //  64 bit
	VA_4S  = (FSZ_S << 1) | 1, // 128 bit
	VA_1D  = (FSZ_D << 1) | 0, //  64 bit
	VA_2D  = (FSZ_D << 1) | 1, // 128 bit
};

/// @brief 浮点数精度
enum FPRounding {
	FPR_CURRENT,  // "Current rounding mode"
	FPR_TIE_EVEN, // N, Nearest with Ties to Even, default IEEE 754 mode
	FPR_TIE_AWAY, // A, Nearest with Ties Away from Zero
	FPR_NEG_INF,  // M, → -∞
	FPR_ZERO,     // Z, → 0
	FPR_POS_INF,  // P, → +∞
	FPR_ODD,      // XN, Non-IEEE 754 Round to Odd, only used by FCVTXN(2)
};


/// @brief 扩展类型
enum ExtendType {
	UXTB = (0 << 2) | SZ_B, 
	UXTH = (0 << 2) | SZ_H,
	UXTW = (0 << 2) | SZ_W,
	UXTX = (0 << 2) | SZ_X,
	SXTB = (1 << 2) | SZ_B,
	SXTH = (1 << 2) | SZ_H,
	SXTW = (1 << 2) | SZ_W,
	SXTX = (1 << 2) | SZ_X,
};

/// @brief 编码MSR_IMM指令修改的PSTATE位
enum PstateField {
	PSF_UAO,        // Unaligned Access
	PSF_PAN,        // Privileged Access
	PSF_SPSel,      // Supervisor Privilege
	PSF_SSBS,       // Stack-Segment Base
	PSF_DIT,        // Data Independent Timing
	PSF_DAIFSet,    // Data Active Interrupts
	PSF_DAIFClr,    // Data Inactive Interrupts
};


/// @brief 特殊寄存器
enum special_registers {
	ZERO_REG = 31,      // 0 寄存器
	STACK_POINTER = 100 // SP 栈指针
};

/// @brief 标志位
enum flagmasks {
	W32 = 1 << 0,         // use the 32-bit W0...W31 facets?
	SET_FLAGS = 1 << 1,   // modify the NZCV flags? (S mnemonic suffix)
	// SIMD: Is scalar? If so, interpret Inst.flags.vec<2:1> as FPSize precision for the scalar.
	SIMD_SCALAR = 1 << 5,
	SIMD_SIGNED = 1 << 6, // Integer SIMD: treat values as signed?
	SIMD_ROUND = 1 << 7,  // Integer SIMD: round result instead of truncating?
};

/// @brief 指令结构体
struct Inst {
    Opcode op;  // 操作码
    u8 flags;   // 指令标志位

    union {
		Reg rd;  // 目的寄存器 - Rd
		Reg rt;  // load 的目的寄存器, store 的源寄存器, CBZ/TBZ operand - Rt (target)
	};

    Reg rn;      // first (or only) operand, read-only - Rn; base addressing register (Xn)
    union {
		Reg rm;  // second operand, read-only - Rm; index register for AM_OFF_REG, AM_OFF_EXT
		Reg rt2; // second destination/source register for LDP, STP and variants (e.g. LDXP)
		Reg rs;  // operand register for atomic operations
	};
    union {
		u64 imm;     // single immediate
		double fimm; // FMOV_IMM 8-bit immediate extended to double
		i64 offset;  // branches, ADR, ADRP: PC-relative byte offset
		Reg ra;      // third operand for 3-source data proc instrs (MADD, etc.)
		char *error; // error string for op = ARM64_ERROR

		struct {
			u32 imm16;
			u32 lsl;   // left shift amount (0, 16, 32, 48)
		} movk;
		struct {
			u32 lsb;
			u32 width;
		} bfm; // BFM aliases: BFXIL, SBFIZ, SBFX, UBFIZ, UBFX
		struct {
			u32 nzcv;
			u32 imm5;
		} ccmp;
		struct {
			u16 op1;   
			u16 op2;
			u16 crn;
			u16 crm;
		} sys; // We don't decode SYS and SYSL further
		struct {
			u32 psfld;  // enum PstateField
			u32 imm;    // imm(4)
		} msr_imm;
		struct {
			i32 offset; // 14-bit jump offset
			u32 bit;    // b5:b40 field -- bit number to be tested
		} tbz;
		struct {
			u32 type;   // enum Shift (not used because sizeof(enum) is impl-defined)
			u32 amount;
		} shift;
		struct {
			u32 mask;
			u32 ror;  // rotate right amount - 0..63
		} rmif;
		struct {
			u32 type; // enum ExtendType
			u32 lsl;  // left shift amount
		} extend;
		struct {
			// Atomics can have different ordering for the load and the store, so
			// we need to have two variables.
			u16 load;  // enum MemOrdering for Load -- None, Acquire, LOAcquire, AcquirePC
			u16 store; // --------------- for Store -- None, Release, LORelease

			Reg rs;    // status register for exclusive store (STXR, STLXR, STXP, STLXP)
		} ldst_order; // atomics and load/stores from Exclusive group
		struct {
			u32 nreg;   // consecutive vector registers to load/store
			u16 index;  // for single-struct variants: index of vector lane to load/store
			i16 offset; // offset to use if AM_POST and offset register Rm == ZERO_REG
		} simd_ldst; // LD1..4, ST1..4
		struct {
			u32 mode;  // rounding mode -- enum FPRounding
			u16 fbits; // 0 → integer conversion; >0 → bits after binary fixed point
			u16 sgn;   // is signed?
		} fcvt; // FCVT, CVTF
		struct {
			u32 mode; // rounding mode -- enum FPRounding
			u32 bits; // 0 → round to integral; 32/64 → round to 32/64-bit int
		} frint;
		struct {
			u32 dst; // destination index
			u32 src; // source index
		} ins_elem; // INS (element)
		struct {
			u32 idx;
			u32 rot;
		} fcmla_elem;
    };
};


#ifndef __cplusplus // C 版本
	Cond arm64_get_cond(u8 flags);
	AddrMode arm64_get_addrmode(u8 flags);
	ExtendType arm64_get_mem_extend(u8 flags);
	VectorArrangement arm64_get_vec_arrangement(u8 flags);
	FPSize arm64_get_prec(u8 flags);
	FPSize arm64_size_from_vec_arrangement(VectorArrangement);
	int arm64_decode(u32 *in, uint n, Inst *out);
    void print_inst(Inst inst);
#else // C++ 版本
}   // namespace hyarmdec
extern "C" {
	hyarmdec::Cond arm64_get_cond(u8 flags);
	hyarmdec::AddrMode arm64_get_addrmode(u8 flags);
	hyarmdec::ExtendType arm64_get_mem_extend(u8 flags);
	hyarmdec::VectorArrangement arm64_get_vec_arrangement(u8 flags);
	hyarmdec::FPSize arm64_get_prec(u8 flags);
	hyarmdec::FPSize arm64_size_from_vec_arrangement(hyarmdec::VectorArrangement);
	int arm64_decode(u32 *in, uint n, hyarmdec::Inst *out);
    void print_inst(hyarmdec::Inst inst);
}
#endif  // __cplusplus




/// ==== 类型定义取消：防止污染 ==== ///
#ifndef HYARMDEC_INTERNAL
#undef uint
#undef u8
#undef u16
#undef u32
#undef u64
#undef i8
#undef i16
#undef i32
#undef i64
#undef f32
#undef f64
#endif // HYARMDEC_INTERNAL



#endif // HYARMDEC_H



