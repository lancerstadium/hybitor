/// \file emulator/decord.hpp
/// \brief RISC-V64 decord 模拟

#ifndef EMULATOR_DECORDER_HPP
#define EMULATOR_DECORDER_HPP


#include "emulator/reg.hpp"
#include "tools/debug.hpp"





// ============================================================================== //
// 指令 insn
// ============================================================================== //
#ifdef _cplusplus
extern "C" {
#endif // _cplusplus

#define QUADRANT(data) (((data) >> 0) & 0x3) // 象限：取最低两位，判断是否压缩指令
#define OPCODE(data) (((data) >> 2) & 0x1f)  // 操作码：取2-6位
#define RD(data) (((data) >> 7) & 0x1f)      // RD：取7-11位
#define RS1(data) (((data) >> 15) & 0x1f)    // 操作数1：取15-19位
#define RS2(data) (((data) >> 20) & 0x1f)    // 操作数2：取20-24位
#define RS3(data) (((data) >> 27) & 0x1f)    // 操作数3：取27-31位
#define FUNCT2(data) (((data) >> 25) & 0x3)
#define FUNCT3(data) (((data) >> 12) & 0x7)
#define FUNCT7(data) (((data) >> 25) & 0x7f)
#define IMM116(data) (((data) >> 26) & 0x3f) // 立即数

/// @brief 指令类型
enum insn_type_t {
    insn_lb, insn_lh, insn_lw, insn_ld, insn_lbu, insn_lhu, insn_lwu,
    insn_fence, insn_fence_i,
    insn_addi, insn_slli, insn_slti, insn_sltiu, insn_xori, insn_srli, insn_srai, insn_ori, insn_andi, insn_auipc, insn_addiw, insn_slliw, insn_srliw, insn_sraiw,
    insn_sb, insn_sh, insn_sw, insn_sd,
    insn_add, insn_sll, insn_slt, insn_sltu, insn_xor, insn_srl, insn_or, insn_and,
    insn_mul, insn_mulh, insn_mulhsu, insn_mulhu, insn_div, insn_divu, insn_rem, insn_remu,
    insn_sub, insn_sra, insn_lui,
    insn_addw, insn_sllw, insn_srlw, insn_mulw, insn_divw, insn_divuw, insn_remw, insn_remuw, insn_subw, insn_sraw,
    insn_beq, insn_bne, insn_blt, insn_bge, insn_bltu, insn_bgeu,
    insn_jalr, insn_jal, insn_ecall,
    insn_csrrc, insn_csrrci, insn_csrrs, insn_csrrsi, insn_csrrw, insn_csrrwi,
    insn_flw, insn_fsw,
    insn_fmadd_s, insn_fmsub_s, insn_fnmsub_s, insn_fnmadd_s, insn_fadd_s, insn_fsub_s, insn_fmul_s, insn_fdiv_s, insn_fsqrt_s,
    insn_fsgnj_s, insn_fsgnjn_s, insn_fsgnjx_s,
    insn_fmin_s, insn_fmax_s,
    insn_fcvt_w_s, insn_fcvt_wu_s, insn_fmv_x_w,
    insn_feq_s, insn_flt_s, insn_fle_s, insn_fclass_s,
    insn_fcvt_s_w, insn_fcvt_s_wu, insn_fmv_w_x, insn_fcvt_l_s, insn_fcvt_lu_s,
    insn_fcvt_s_l, insn_fcvt_s_lu,
    insn_fld, insn_fsd,
    insn_fmadd_d, insn_fmsub_d, insn_fnmsub_d, insn_fnmadd_d,
    insn_fadd_d, insn_fsub_d, insn_fmul_d, insn_fdiv_d, insn_fsqrt_d,
    insn_fsgnj_d, insn_fsgnjn_d, insn_fsgnjx_d,
    insn_fmin_d, insn_fmax_d,
    insn_fcvt_s_d, insn_fcvt_d_s,
    insn_feq_d, insn_flt_d, insn_fle_d, insn_fclass_d,
    insn_fcvt_w_d, insn_fcvt_wu_d, insn_fcvt_d_w, insn_fcvt_d_wu,
    insn_fcvt_l_d, insn_fcvt_lu_d,
    insn_fmv_x_d, insn_fcvt_d_l, insn_fcvt_d_lu, insn_fmv_d_x,
    num_insns,
};

/// @brief 指令结构体
typedef struct {
    i8 rd;      // 操作码
    i8 rs1;     // 寄存器1
    i8 rs2;     // 寄存器2
    i8 rs3;     // 寄存器3
    i16 csr;    // csr数
    i32 imm;    // 立即数
    enum insn_type_t type;  // 指令类型
    bool rvc;   // 是否 rvc 压缩指令
    bool cont;  // 是否继续执行
} insn_t;


static inline insn_t insn_utype_read(u32 data)
{
    insn_t insn;
    insn.imm = static_cast<i32>(data & 0xfffff000);
    insn.rd = static_cast<i8>(RD(data));
    return insn;
}

static inline insn_t insn_itype_read(u32 data)
{
    insn_t insn;
    insn.imm = (i32)data >> 20;
    insn.rs1 = static_cast<i8>(RS1(data));
    insn.rd = static_cast<i8>(RD(data));
    return insn;
}

static inline insn_t insn_jtype_read(u32 data)
{
    insn_t insn;
    u32 imm20 = (data >> 31) & 0x1;
    u32 imm101 = (data >> 21) & 0x3ff;
    u32 imm11 = (data >> 20) & 0x1;
    u32 imm1912 = (data >> 12) & 0xff;

    i32 imm = (imm20 << 20) | (imm1912 << 12) | (imm11 << 11) | (imm101 << 1);
    imm = (imm << 11) >> 11;

    insn.imm = imm;
    insn.rd = static_cast<i8>(RD(data));

    return insn;
}

static inline insn_t insn_btype_read(u32 data)
{
    insn_t insn;
    u32 imm12 = (data >> 31) & 0x1;
    u32 imm105 = (data >> 25) & 0x3f;
    u32 imm41 = (data >> 8) & 0xf;
    u32 imm11 = (data >> 7) & 0x1;

    i32 imm = (imm12 << 12) | (imm11 << 11) | (imm105 << 5) | (imm41 << 1);
    imm = (imm << 19) >> 19;

    insn.imm = imm;
    insn.rs1 = static_cast<i8>(RS1(data));
    insn.rs2 = static_cast<i8>(RS2(data));

    return insn;
}

static inline insn_t insn_rtype_read(u32 data)
{
    insn_t insn;
    insn.rs1 = static_cast<i8>(RS1(data));
    insn.rs2 = static_cast<i8>(RS2(data));
    insn.rd = static_cast<i8>(RD(data));
    return insn;
}

static inline insn_t insn_stype_read(u32 data)
{
    insn_t insn;
    u32 imm115 = (data >> 25) & 0x7f;
    u32 imm40 = (data >> 7) & 0x1f;

    i32 imm = (imm115 << 5) | imm40;
    imm = (imm << 20) >> 20;

    insn.imm = imm;
    insn.rs1 = static_cast<i8>(RS1(data));
    insn.rs2 = static_cast<i8>(RS2(data));

    return insn;
}

static inline insn_t insn_csrtype_read(u32 data)
{
    insn_t insn;
    insn.csr = static_cast<i16>(data >> 20);
    insn.rs1 = static_cast<i8>(RS1(data));
    insn.rd = static_cast<i8>(RD(data));

    return insn;
}

static inline insn_t insn_fprtype_read(u32 data)
{
    insn_t insn;
    insn.rs1 = static_cast<i8>(RS1(data));
    insn.rs2 = static_cast<i8>(RS2(data));
    insn.rs3 = static_cast<i8>(RS3(data));
    insn.rd = static_cast<i8>(RD(data));

    return insn;
}

/**
 * compressed types
 */
#define COPCODE(data) (((data) >> 13) & 0x7)
#define CFUNCT1(data) (((data) >> 12) & 0x1)
#define CFUNCT2LOW(data) (((data) >> 5) & 0x3)
#define CFUNCT2HIGH(data) (((data) >> 10) & 0x3)
#define RP1(data) (((data) >> 7) & 0x7)
#define RP2(data) (((data) >> 2) & 0x7)
#define RC1(data) (((data) >> 7) & 0x1f)
#define RC2(data) (((data) >> 2) & 0x1f)

static inline insn_t insn_catype_read(u16 data)
{
    insn_t insn;
    insn.rd = static_cast<i8>(RP1(data) + 8);
    insn.rs2 = static_cast<i8>(RP2(data) + 8);
    insn.rvc = true;
    return insn;
}

static inline insn_t insn_crtype_read(u16 data)
{
    insn_t insn;
    insn.rs1 = static_cast<i8>(RC1(data));
    insn.rs2 = static_cast<i8>(RC2(data));
    insn.rvc = true;
    return insn;
}

static inline insn_t insn_citype_read(u16 data)
{
    insn_t insn;
    u32 imm40 = (data >> 2) & 0x1f;
    u32 imm5 = (data >> 12) & 0x1;
    i32 imm = (imm5 << 5) | imm40;
    imm = (imm << 26) >> 26;

    insn.imm = imm;
    insn.rd = static_cast<i8>(RC1(data));
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_citype_read2(u16 data)
{
    insn_t insn;
    u32 imm86 = (data >> 2) & 0x7;
    u32 imm43 = (data >> 5) & 0x3;
    u32 imm5 = (data >> 12) & 0x1;

    i32 imm = (imm86 << 6) | (imm43 << 3) | (imm5 << 5);

    insn.imm = imm;
    insn.rd = static_cast<i8>(RC1(data));
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_citype_read3(u16 data)
{
    insn_t insn;
    u32 imm5 = (data >> 2) & 0x1;
    u32 imm87 = (data >> 3) & 0x3;
    u32 imm6 = (data >> 5) & 0x1;
    u32 imm4 = (data >> 6) & 0x1;
    u32 imm9 = (data >> 12) & 0x1;

    i32 imm = (imm5 << 5) | (imm87 << 7) | (imm6 << 6) | (imm4 << 4) | (imm9 << 9);
    imm = (imm << 22) >> 22;

    insn.imm = imm;
    insn.rd = static_cast<i8>(RC1(data));
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_citype_read4(u16 data)
{
    insn_t insn;
    u32 imm5 = (data >> 12) & 0x1;
    u32 imm42 = (data >> 4) & 0x7;
    u32 imm76 = (data >> 2) & 0x3;

    i32 imm = (imm5 << 5) | (imm42 << 2) | (imm76 << 6);

    insn.imm = imm;
    insn.rd = static_cast<i8>(RC1(data));
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_citype_read5(u16 data)
{
    insn_t insn;
    u32 imm1612 = (data >> 2) & 0x1f;
    u32 imm17 = (data >> 12) & 0x1;

    i32 imm = (imm1612 << 12) | (imm17 << 17);
    imm = (imm << 14) >> 14;

    insn.imm = imm;
    insn.rd = static_cast<i8>(RC1(data));
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_cbtype_read(u16 data)
{
    insn_t insn;
    u32 imm5 = (data >> 2) & 0x1;
    u32 imm21 = (data >> 3) & 0x3;
    u32 imm76 = (data >> 5) & 0x3;
    u32 imm43 = (data >> 10) & 0x3;
    u32 imm8 = (data >> 12) & 0x1;

    i32 imm = (imm8 << 8) | (imm76 << 6) | (imm5 << 5) | (imm43 << 3) | (imm21 << 1);
    imm = (imm << 23) >> 23;

    insn.imm = imm;
    insn.rs1 = static_cast<i8>(RP1(data) + 8);
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_cbtype_read2(u16 data)
{
    insn_t insn;
    u32 imm40 = (data >> 2) & 0x1f;
    u32 imm5 = (data >> 12) & 0x1;
    i32 imm = (imm5 << 5) | imm40;
    imm = (imm << 26) >> 26;

    insn.imm = imm;
    insn.rd = static_cast<i8>(RP1(data) + 8);
    insn.rvc = true;
    return insn;
}

static inline insn_t insn_cstype_read(u16 data)
{
    insn_t insn;
    u32 imm76 = (data >> 5) & 0x3;
    u32 imm53 = (data >> 10) & 0x7;

    i32 imm = ((imm76 << 6) | (imm53 << 3));

    insn.imm = imm;
    insn.rs1 = static_cast<i8>(RP1(data) + 8);
    insn.rs2 = static_cast<i8>(RP2(data) + 8);
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_cstype_read2(u16 data)
{
    insn_t insn;
    u32 imm6 = (data >> 5) & 0x1;
    u32 imm2 = (data >> 6) & 0x1;
    u32 imm53 = (data >> 10) & 0x7;

    i32 imm = ((imm6 << 6) | (imm2 << 2) | (imm53 << 3));

    insn.imm = imm;
    insn.rs1 = static_cast<i8>(RP1(data) + 8);
    insn.rs2 = static_cast<i8>(RP2(data) + 8);
    insn.rvc = true;


    return insn;
}

static inline insn_t insn_cjtype_read(u16 data)
{
    insn_t insn;
    u32 imm5 = (data >> 2) & 0x1;
    u32 imm31 = (data >> 3) & 0x7;
    u32 imm7 = (data >> 6) & 0x1;
    u32 imm6 = (data >> 7) & 0x1;
    u32 imm10 = (data >> 8) & 0x1;
    u32 imm98 = (data >> 9) & 0x3;
    u32 imm4 = (data >> 11) & 0x1;
    u32 imm11 = (data >> 12) & 0x1;

    i32 imm = ((imm5 << 5) | (imm31 << 1) | (imm7 << 7) | (imm6 << 6) |
               (imm10 << 10) | (imm98 << 8) | (imm4 << 4) | (imm11 << 11));
    imm = (imm << 20) >> 20;

    insn.imm = imm;
    insn.rvc = true;
    return insn;
}

static inline insn_t insn_cltype_read(u16 data)
{
    insn_t insn;
    u32 imm6 = (data >> 5) & 0x1;
    u32 imm2 = (data >> 6) & 0x1;
    u32 imm53 = (data >> 10) & 0x7;

    i32 imm = (imm6 << 6) | (imm2 << 2) | (imm53 << 3);

    insn.imm = imm;
    insn.rs1 = static_cast<i8>(RP1(data) + 8);
    insn.rd = static_cast<i8>(RP2(data) + 8);
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_cltype_read2(u16 data)
{
    insn_t insn;
    u32 imm76 = (data >> 5) & 0x3;
    u32 imm53 = (data >> 10) & 0x7;

    i32 imm = (imm76 << 6) | (imm53 << 3);

    insn.imm = imm;
    insn.rs1 = static_cast<i8>(RP1(data) + 8);
    insn.rd = static_cast<i8>(RP2(data) + 8);
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_csstype_read(u16 data)
{
    insn_t insn;
    u32 imm86 = (data >> 7) & 0x7;
    u32 imm53 = (data >> 10) & 0x7;

    i32 imm = (imm86 << 6) | (imm53 << 3);

    insn.imm = imm;
    insn.rs2 = static_cast<i8>(RC2(data));
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_csstype_read2(u16 data)
{
    insn_t insn;
    u32 imm76 = (data >> 7) & 0x3;
    u32 imm52 = (data >> 9) & 0xf;

    i32 imm = (imm76 << 6) | (imm52 << 2);

    insn.imm = imm;
    insn.rs2 = static_cast<i8>(RC2(data));
    insn.rvc = true;

    return insn;
}

static inline insn_t insn_ciwtype_read(u16 data)
{
    insn_t insn;
    u32 imm3 = (data >> 5) & 0x1;
    u32 imm2 = (data >> 6) & 0x1;
    u32 imm96 = (data >> 7) & 0xf;
    u32 imm54 = (data >> 11) & 0x3;

    i32 imm = (imm3 << 3) | (imm2 << 2) | (imm96 << 6) | (imm54 << 4);

    insn.imm = imm;
    insn.rd = static_cast<i8>(RP2(data) + 8);
    insn.rvc = true;
    
    return insn;
}

#ifdef _cplusplus
} // extern "C"
#endif // _cplusplus

// ==================================================================================== //
// decoder
// ==================================================================================== //



enum INST_NAME {
        //RV64I
        LUI, AUIPC, JAL, JALR,
        BEQ, BNE, BLT, BGE, BLTU, BGEU,
        LB, LH, LW, LBU, LHU,
        SB, SH, SW,
        ADDI, SLTI, SLTIU, XORI, ORI, ANDI,
        SLLI, SRLI, SRAI,
        ADD, SUB, SLL, SLT, SLTU,
        XOR, SRL, SRA, OR,
        AND, FENCE, ECALL, EBREAK,
        LWU, LD, SD,
        ADDIW, SLLIW, SRLIW, SRAIW,
        ADDW, SUBW, SLLW, SRLW, SRAW,
        //Zicsr
        CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI,
        //trap return
        MRET, SRET,
        //end
        INST_NUM,
};

class decoder {
public:

    bool riscv_tests;
    u32 inst_val;

    enum INST_NAME inst_name;

    u64 dest;
    u64 src1;
    u64 src2;
    u64 imm;
    u64 csr_addr;
    int rd;
    int rs1;
    int rs2;
    int shamt;
    u64 snpc;
    u64 dnpc;


    decoder() {}

    /// @brief 根据指令初始化解码器
    /// @param inst 
    void set_decoder(u32 inst)
    {
        this->inst_val = inst;
        this->rd = BITS(inst, 11, 7);
        this->rs1 = BITS(inst, 19, 15);
        this->rs2 = BITS(inst, 24, 20);
        this->shamt = BITS(inst, 25, 20);
        this->csr_addr = BITS(inst, 31, 20);
        u32 funct3 = BITS(inst, 14, 12);
        u32 funct7 = BITS(inst, 31, 25);
        u32 funct6 = BITS(inst, 31, 26);
        u32 opcode = BITS(inst, 6, 0);
        switch (opcode)
        {
        case 0b0110111:
            this->inst_name = LUI;
            this->imm = imm_u(inst);
            break;
        case 0b0010111:
            this->inst_name = AUIPC;
            this->imm = imm_u(inst);
            break;
        case 0b1101111:
            this->inst_name = JAL;
            this->imm = imm_j(inst);
            break;
        case 0b1100111:
            this->inst_name = JALR;
            this->imm = imm_i(inst);
            break;
        case 0b1100011:
            this->imm = imm_b(inst);
            switch (funct3)
            {
            case 0b000:
                this->inst_name = BEQ;
                break;
            case 0b001:
                this->inst_name = BNE;
                break;
            case 0b100:
                this->inst_name = BLT;
                break;
            case 0b101:
                this->inst_name = BGE;
                break;
            case 0b110:
                this->inst_name = BLTU;
                break;
            case 0b111:
                this->inst_name = BGEU;
                break;
            }
            break;
        case 0b0000011:
            this->imm = imm_i(inst);
            switch (funct3)
            {
            case 0b000:
                this->inst_name = LB;
                break;
            case 0b001:
                this->inst_name = LH;
                break;
            case 0b010:
                this->inst_name = LW;
                break;
            case 0b100:
                this->inst_name = LBU;
                break;
            case 0b101:
                this->inst_name = LHU;
                break;
            case 0b110:
                this->inst_name = LWU;
                break;
            case 0b011:
                this->inst_name = LD;
                break;
            }
            break;
        case 0b0100011:
            this->imm = imm_s(inst);
            printf("imm_s == 0x%llx\n", (long long unsigned)this->imm);
            switch (funct3)
            {
            case 0b000:
                this->inst_name = SB;
                break;
            case 0b001:
                this->inst_name = SH;
                break;
            case 0b010:
                this->inst_name = SW;
                break;
            case 0b011:
                this->inst_name = SD;
                break;
            }
            break;
        case 0b0010011:
            this->imm = imm_i(inst);
            switch (funct3)
            {
            case 0b000:
                this->inst_name = ADDI;
                break;
            case 0b010:
                this->inst_name = SLTI;
                break;
            case 0b011:
                this->inst_name = SLTIU;
                break;
            case 0b100:
                this->inst_name = XORI;
                break;
            case 0b110:
                this->inst_name = ORI;
                break;
            case 0b111:
                this->inst_name = ANDI;
                break;
            case 0b001:
                this->inst_name = SLLI;
                break;
            case 0b101:
                switch (funct6)
                {
                case 0:
                    this->inst_name = SRLI;
                    break;
                case 0b10000:
                    this->inst_name = SRAI;
                    break;
                }
                break;
            }
            break;
        case 0b0110011:
            switch ((funct7 << 3) | funct3)
            {
            case 0:
                this->inst_name = ADD;
                break;
            case 0b100000000:
                this->inst_name = SUB;
                break;
            case 0b1:
                this->inst_name = SLL;
                break;
            case 0b10:
                this->inst_name = SLT;
                break;
            case 0b11:
                this->inst_name = SLTU;
                break;
            case 0b100:
                this->inst_name = XOR;
                break;
            case 0b101:
                this->inst_name = SRL;
                break;
            case 0b100000101:
                this->inst_name = SRA;
                break;
            case 0b110:
                this->inst_name = OR;
                break;
            case 0b111:
                this->inst_name = AND;
                break;
            }
            break;
        case 0b0001111:
            switch (funct3)
            {
            case 0:
                this->inst_name = FENCE;
                break;
            case 1:
                // fence_i
                // implement as NOP
                this->inst_name = FENCE;
                break;
            default:
                this->inst_name = INST_NUM;
                break;
            }
            break;
        case 0b1110011:
            if (funct3 != 0)
            {
                // csr
                switch (funct3)
                {
                case 0b001:
                    this->inst_name = CSRRW;
                    break;
                case 0b010:
                    this->inst_name = CSRRS;
                    break;
                case 0b011:
                    this->inst_name = CSRRC;
                    break;
                case 0b101:
                    this->inst_name = CSRRWI;
                    break;
                case 0b110:
                    this->inst_name = CSRRSI;
                    break;
                case 0b111:
                    this->inst_name = CSRRCI;
                    break;
                default:
                    this->inst_name = INST_NUM;
                    break;
                }
            }
            else
            {
                switch ((funct7 << 5) | this->rs2)
                {
                case 0:
                    this->inst_name = ECALL;
                    break;
                case 1:
                    this->inst_name = EBREAK;
                    break;
                case 0b100000010:
                    this->inst_name = SRET;
                    break;
                case 0b1100000010:
                    this->inst_name = MRET;
                    break;
                default:
                    this->inst_name = INST_NUM;
                    break;
                }
            }

            break;
        case 0b0011011:
            switch (funct3)
            {
            case 0:
                this->imm = imm_i(inst);
                this->inst_name = ADDIW;
                break;
            case 0b001:
                switch (funct7)
                {
                case 0:
                    this->inst_name = SLLIW;
                    break;
                default:
                    this->inst_name = INST_NUM;
                    break;
                }
                break;
            case 0b101:
                switch (funct7)
                {
                case 0:
                    this->inst_name = SRLIW;
                    break;
                case 0b100000:
                    this->inst_name = SRAIW;
                    break;
                }
                break;
            default:
                this->inst_name = INST_NUM;
                break;
            }
            break;
        case 0b0111011:
            switch ((funct7 << 3) | funct3)
            {
            case 0b0:
                this->inst_name = ADDW;
                break;
            case 0b0100000000:
                this->inst_name = SUBW;
                break;
            case 0b1:
                this->inst_name = SLLW;
                break;
            case 0b101:
                this->inst_name = SRLW;
                break;
            case 0b100000101:
                this->inst_name = SRAW;
                break;
            default:
                this->inst_name = INST_NUM;
                break;
            }
            break;
        default:
            this->inst_name = INST_NUM;
        }
    }

    ~decoder() {}

    /// @brief 解码指令
    /// @param insn 指令
    /// @param data 数据
    void insn_decode(insn_t *insn, u32 data)
    {
        u32 quadrant = QUADRANT(data);
        switch (quadrant)
        {
        case 0x0:
        {
            u32 copcode = COPCODE(data);

            switch (copcode)
            {
            case 0x0: /* C.ADDI4SPN */
                *insn = insn_ciwtype_read(data);
                insn->rs1 = sp;
                insn->type = insn_addi;
                assert(insn->imm != 0);
                return;
            case 0x1: /* C.FLD */
                *insn = insn_cltype_read2(data);
                insn->type = insn_fld;
                return;
            case 0x2: /* C.LW */
                *insn = insn_cltype_read(data);
                insn->type = insn_lw;
                return;
            case 0x3: /* C.LD */
                *insn = insn_cltype_read2(data);
                insn->type = insn_ld;
                return;
            case 0x5: /* C.FSD */
                *insn = insn_cstype_read(data);
                insn->type = insn_fsd;
                return;
            case 0x6: /* C.SW */
                *insn = insn_cstype_read2(data);
                insn->type = insn_sw;
                return;
            case 0x7: /* C.SD */
                *insn = insn_cstype_read(data);
                insn->type = insn_sd;
                return;
            default:
                printf("data: %x\n", data);
                fatal("unimplemented");
            }
        }
            unreachable();
        case 0x1:
        {
            u32 copcode = COPCODE(data);

            switch (copcode)
            {
            case 0x0: /* C.ADDI */
                *insn = insn_citype_read(data);
                insn->rs1 = insn->rd;
                insn->type = insn_addi;
                return;
            case 0x1: /* C.ADDIW */
                *insn = insn_citype_read(data);
                assert(insn->rd != 0);
                insn->rs1 = insn->rd;
                insn->type = insn_addiw;
                return;
            case 0x2: /* C.LI */
                *insn = insn_citype_read(data);
                insn->rs1 = zero;
                insn->type = insn_addi;
                return;
            case 0x3:
            {
                i32 rd = static_cast<i8>(RC1(data));
                if (rd == 2)
                { /* C.ADDI16SP */
                    *insn = insn_citype_read3(data);
                    assert(insn->imm != 0);
                    insn->rs1 = insn->rd;
                    insn->type = insn_addi;
                    return;
                }
                else
                { /* C.LUI */
                    *insn = insn_citype_read5(data);
                    assert(insn->imm != 0);
                    insn->type = insn_lui;
                    return;
                }
            }
                unreachable();
            case 0x4:
            {
                u32 cfunct2high = CFUNCT2HIGH(data);

                switch (cfunct2high)
                {
                case 0x0: /* C.SRLI */
                case 0x1: /* C.SRAI */
                case 0x2:
                { /* C.ANDI */
                    *insn = insn_cbtype_read2(data);
                    insn->rs1 = insn->rd;

                    if (cfunct2high == 0x0)
                    {
                        insn->type = insn_srli;
                    }
                    else if (cfunct2high == 0x1)
                    {
                        insn->type = insn_srai;
                    }
                    else
                    {
                        insn->type = insn_andi;
                    }
                    return;
                }
                    unreachable();
                case 0x3:
                {
                    u32 cfunct1 = CFUNCT1(data);

                    switch (cfunct1)
                    {
                    case 0x0:
                    {
                        u32 cfunct2low = CFUNCT2LOW(data);

                        *insn = insn_catype_read(data);
                        insn->rs1 = insn->rd;

                        switch (cfunct2low)
                        {
                        case 0x0: /* C.SUB */
                            insn->type = insn_sub;
                            break;
                        case 0x1: /* C.XOR */
                            insn->type = insn_xor;
                            break;
                        case 0x2: /* C.OR */
                            insn->type = insn_or;
                            break;
                        case 0x3: /* C.AND */
                            insn->type = insn_and;
                            break;
                        default:
                            unreachable();
                        }
                        return;
                    }
                        unreachable();
                    case 0x1:
                    {
                        u32 cfunct2low = CFUNCT2LOW(data);

                        *insn = insn_catype_read(data);
                        insn->rs1 = insn->rd;

                        switch (cfunct2low)
                        {
                        case 0x0: /* C.SUBW */
                            insn->type = insn_subw;
                            break;
                        case 0x1: /* C.ADDW */
                            insn->type = insn_addw;
                            break;
                        default:
                            unreachable();
                        }
                        return;
                    }
                        unreachable();
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x5: /* C.J */
                *insn = insn_cjtype_read(data);
                insn->rd = zero;
                insn->type = insn_jal;
                insn->cont = true;
                return;
            case 0x6: /* C.BEQZ */
            case 0x7: /* C.BNEZ */
                *insn = insn_cbtype_read(data);
                insn->rs2 = zero;
                insn->type = copcode == 0x6 ? insn_beq : insn_bne;
                return;
            default:
                fatal("unrecognized copcode");
            }
        }
            unreachable();
        case 0x2:
        {
            u32 copcode = COPCODE(data);
            switch (copcode)
            {
            case 0x0: /* C.SLLI */
                *insn = insn_citype_read(data);
                insn->rs1 = insn->rd;
                insn->type = insn_slli;
                return;
            case 0x1: /* C.FLDSP */
                *insn = insn_citype_read2(data);
                insn->rs1 = sp;
                insn->type = insn_fld;
                return;
            case 0x2: /* C.LWSP */
                *insn = insn_citype_read4(data);
                assert(insn->rd != 0);
                insn->rs1 = sp;
                insn->type = insn_lw;
                return;
            case 0x3: /* C.LDSP */
                *insn = insn_citype_read2(data);
                assert(insn->rd != 0);
                insn->rs1 = sp;
                insn->type = insn_ld;
                return;
            case 0x4:
            {
                u32 cfunct1 = CFUNCT1(data);

                switch (cfunct1)
                {
                case 0x0:
                {
                    *insn = insn_crtype_read(data);

                    if (insn->rs2 == 0)
                    { /* C.JR */
                        assert(insn->rs1 != 0);
                        insn->rd = zero;
                        insn->type = insn_jalr;
                        insn->cont = true;
                    }
                    else
                    { /* C.MV */
                        insn->rd = insn->rs1;
                        insn->rs1 = zero;
                        insn->type = insn_add;
                    }
                    return;
                }
                    unreachable();
                case 0x1:
                {
                    *insn = insn_crtype_read(data);
                    if (insn->rs1 == 0 && insn->rs2 == 0)
                    { /* C.EBREAK */
                        fatal("unimplmented");
                    }
                    else if (insn->rs2 == 0)
                    { /* C.JALR */
                        insn->rd = ra;
                        insn->type = insn_jalr;
                        insn->cont = true;
                    }
                    else
                    { /* C.ADD */
                        insn->rd = insn->rs1;
                        insn->type = insn_add;
                    }
                    return;
                }
                    unreachable();
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x5: /* C.FSDSP */
                *insn = insn_csstype_read(data);
                insn->rs1 = sp;
                insn->type = insn_fsd;
                return;
            case 0x6: /* C.SWSP */
                *insn = insn_csstype_read2(data);
                insn->rs1 = sp;
                insn->type = insn_sw;
                return;
            case 0x7: /* C.SDSP */
                *insn = insn_csstype_read(data);
                insn->rs1 = sp;
                insn->type = insn_sd;
                return;
            default:
                fatal("unrecognized copcode");
            }
        }
            unreachable();
        case 0x3:
        {
            u32 opcode = OPCODE(data);
            switch (opcode)
            {
            case 0x0:
            {
                u32 funct3 = FUNCT3(data);

                *insn = insn_itype_read(data);
                switch (funct3)
                {
                case 0x0: /* LB */
                    insn->type = insn_lb;
                    return;
                case 0x1: /* LH */
                    insn->type = insn_lh;
                    return;
                case 0x2: /* LW */
                    insn->type = insn_lw;
                    return;
                case 0x3: /* LD */
                    insn->type = insn_ld;
                    return;
                case 0x4: /* LBU */
                    insn->type = insn_lbu;
                    return;
                case 0x5: /* LHU */
                    insn->type = insn_lhu;
                    return;
                case 0x6: /* LWU */
                    insn->type = insn_lwu;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x1:
            {
                u32 funct3 = FUNCT3(data);

                *insn = insn_itype_read(data);
                switch (funct3)
                {
                case 0x2: /* FLW */
                    insn->type = insn_flw;
                    return;
                case 0x3: /* FLD */
                    insn->type = insn_fld;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x3:
            {
                u32 funct3 = FUNCT3(data);

                switch (funct3)
                {
                case 0x0:
                { /* FENCE */
                    insn_t _insn = {0};
                    *insn = _insn;
                    insn->type = insn_fence;
                    return;
                }
                case 0x1:
                { /* FENCE.I */
                    insn_t _insn = {0};
                    *insn = _insn;
                    insn->type = insn_fence_i;
                    return;
                }
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x4:
            {
                u32 funct3 = FUNCT3(data);

                *insn = insn_itype_read(data);
                switch (funct3)
                {
                case 0x0: /* ADDI */
                    insn->type = insn_addi;
                    return;
                case 0x1:
                {
                    u32 imm116 = IMM116(data);
                    if (imm116 == 0)
                    { /* SLLI */
                        insn->type = insn_slli;
                    }
                    else
                    {
                        unreachable();
                    }
                    return;
                }
                    unreachable();
                case 0x2: /* SLTI */
                    insn->type = insn_slti;
                    return;
                case 0x3: /* SLTIU */
                    insn->type = insn_sltiu;
                    return;
                case 0x4: /* XORI */
                    insn->type = insn_xori;
                    return;
                case 0x5:
                {
                    u32 imm116 = IMM116(data);

                    if (imm116 == 0x0)
                    { /* SRLI */
                        insn->type = insn_srli;
                    }
                    else if (imm116 == 0x10)
                    { /* SRAI */
                        insn->type = insn_srai;
                    }
                    else
                    {
                        unreachable();
                    }
                    return;
                }
                    unreachable();
                case 0x6: /* ORI */
                    insn->type = insn_ori;
                    return;
                case 0x7: /* ANDI */
                    insn->type = insn_andi;
                    return;
                default:
                    fatal("unrecognized funct3");
                }
            }
                unreachable();
            case 0x5: /* AUIPC */
                *insn = insn_utype_read(data);
                insn->type = insn_auipc;
                return;
            case 0x6:
            {
                u32 funct3 = FUNCT3(data);
                u32 funct7 = FUNCT7(data);

                *insn = insn_itype_read(data);

                switch (funct3)
                {
                case 0x0: /* ADDIW */
                    insn->type = insn_addiw;
                    return;
                case 0x1: /* SLLIW */
                    assert(funct7 == 0);
                    insn->type = insn_slliw;
                    return;
                case 0x5:
                {
                    switch (funct7)
                    {
                    case 0x0: /* SRLIW */
                        insn->type = insn_srliw;
                        return;
                    case 0x20: /* SRAIW */
                        insn->type = insn_sraiw;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                default:
                    fatal("unimplemented");
                }
            }
                unreachable();
            case 0x8:
            {
                u32 funct3 = FUNCT3(data);

                *insn = insn_stype_read(data);
                switch (funct3)
                {
                case 0x0: /* SB */
                    insn->type = insn_sb;
                    return;
                case 0x1: /* SH */
                    insn->type = insn_sh;
                    return;
                case 0x2: /* SW */
                    insn->type = insn_sw;
                    return;
                case 0x3: /* SD */
                    insn->type = insn_sd;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x9:
            {
                u32 funct3 = FUNCT3(data);

                *insn = insn_stype_read(data);
                switch (funct3)
                {
                case 0x2: /* FSW */
                    insn->type = insn_fsw;
                    return;
                case 0x3: /* FSD */
                    insn->type = insn_fsd;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0xc:
            {
                *insn = insn_rtype_read(data);

                u32 funct3 = FUNCT3(data);
                u32 funct7 = FUNCT7(data);

                switch (funct7)
                {
                case 0x0:
                {
                    switch (funct3)
                    {
                    case 0x0: /* ADD */
                        insn->type = insn_add;
                        return;
                    case 0x1: /* SLL */
                        insn->type = insn_sll;
                        return;
                    case 0x2: /* SLT */
                        insn->type = insn_slt;
                        return;
                    case 0x3: /* SLTU */
                        insn->type = insn_sltu;
                        return;
                    case 0x4: /* XOR */
                        insn->type = insn_xor;
                        return;
                    case 0x5: /* SRL */
                        insn->type = insn_srl;
                        return;
                    case 0x6: /* OR */
                        insn->type = insn_or;
                        return;
                    case 0x7: /* AND */
                        insn->type = insn_and;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x1:
                {
                    switch (funct3)
                    {
                    case 0x0: /* MUL */
                        insn->type = insn_mul;
                        return;
                    case 0x1: /* MULH */
                        insn->type = insn_mulh;
                        return;
                    case 0x2: /* MULHSU */
                        insn->type = insn_mulhsu;
                        return;
                    case 0x3: /* MULHU */
                        insn->type = insn_mulhu;
                        return;
                    case 0x4: /* DIV */
                        insn->type = insn_div;
                        return;
                    case 0x5: /* DIVU */
                        insn->type = insn_divu;
                        return;
                    case 0x6: /* REM */
                        insn->type = insn_rem;
                        return;
                    case 0x7: /* REMU */
                        insn->type = insn_remu;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x20:
                {
                    switch (funct3)
                    {
                    case 0x0: /* SUB */
                        insn->type = insn_sub;
                        return;
                    case 0x5: /* SRA */
                        insn->type = insn_sra;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0xd: /* LUI */
                *insn = insn_utype_read(data);
                insn->type = insn_lui;
                return;
            case 0xe:
            {
                *insn = insn_rtype_read(data);

                u32 funct3 = FUNCT3(data);
                u32 funct7 = FUNCT7(data);

                switch (funct7)
                {
                case 0x0:
                {
                    switch (funct3)
                    {
                    case 0x0: /* ADDW */
                        insn->type = insn_addw;
                        return;
                    case 0x1: /* SLLW */
                        insn->type = insn_sllw;
                        return;
                    case 0x5: /* SRLW */
                        insn->type = insn_srlw;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x1:
                {
                    switch (funct3)
                    {
                    case 0x0: /* MULW */
                        insn->type = insn_mulw;
                        return;
                    case 0x4: /* DIVW */
                        insn->type = insn_divw;
                        return;
                    case 0x5: /* DIVUW */
                        insn->type = insn_divuw;
                        return;
                    case 0x6: /* REMW */
                        insn->type = insn_remw;
                        return;
                    case 0x7: /* REMUW */
                        insn->type = insn_remuw;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x20:
                {
                    switch (funct3)
                    {
                    case 0x0: /* SUBW */
                        insn->type = insn_subw;
                        return;
                    case 0x5: /* SRAW */
                        insn->type = insn_sraw;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x10:
            {
                u32 funct2 = FUNCT2(data);

                *insn = insn_fprtype_read(data);
                switch (funct2)
                {
                case 0x0: /* FMADD.S */
                    insn->type = insn_fmadd_s;
                    return;
                case 0x1: /* FMADD.D */
                    insn->type = insn_fmadd_d;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x11:
            {
                u32 funct2 = FUNCT2(data);

                *insn = insn_fprtype_read(data);
                switch (funct2)
                {
                case 0x0: /* FMSUB.S */
                    insn->type = insn_fmsub_s;
                    return;
                case 0x1: /* FMSUB.D */
                    insn->type = insn_fmsub_d;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x12:
            {
                u32 funct2 = FUNCT2(data);

                *insn = insn_fprtype_read(data);
                switch (funct2)
                {
                case 0x0: /* FNMSUB.S */
                    insn->type = insn_fnmsub_s;
                    return;
                case 0x1: /* FNMSUB.D */
                    insn->type = insn_fnmsub_d;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x13:
            {
                u32 funct2 = FUNCT2(data);

                *insn = insn_fprtype_read(data);
                switch (funct2)
                {
                case 0x0: /* FNMADD.S */
                    insn->type = insn_fnmadd_s;
                    return;
                case 0x1: /* FNMADD.D */
                    insn->type = insn_fnmadd_d;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x14:
            {
                u32 funct7 = FUNCT7(data);

                *insn = insn_rtype_read(data);
                switch (funct7)
                {
                case 0x0: /* FADD.S */
                    insn->type = insn_fadd_s;
                    return;
                case 0x1: /* FADD.D */
                    insn->type = insn_fadd_d;
                    return;
                case 0x4: /* FSUB.S */
                    insn->type = insn_fsub_s;
                    return;
                case 0x5: /* FSUB.D */
                    insn->type = insn_fsub_d;
                    return;
                case 0x8: /* FMUL.S */
                    insn->type = insn_fmul_s;
                    return;
                case 0x9: /* FMUL.D */
                    insn->type = insn_fmul_d;
                    return;
                case 0xc: /* FDIV.S */
                    insn->type = insn_fdiv_s;
                    return;
                case 0xd: /* FDIV.D */
                    insn->type = insn_fdiv_d;
                    return;
                case 0x10:
                {
                    u32 funct3 = FUNCT3(data);

                    switch (funct3)
                    {
                    case 0x0: /* FSGNJ.S */
                        insn->type = insn_fsgnj_s;
                        return;
                    case 0x1: /* FSGNJN.S */
                        insn->type = insn_fsgnjn_s;
                        return;
                    case 0x2: /* FSGNJX.S */
                        insn->type = insn_fsgnjx_s;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x11:
                {
                    u32 funct3 = FUNCT3(data);

                    switch (funct3)
                    {
                    case 0x0: /* FSGNJ.D */
                        insn->type = insn_fsgnj_d;
                        return;
                    case 0x1: /* FSGNJN.D */
                        insn->type = insn_fsgnjn_d;
                        return;
                    case 0x2: /* FSGNJX.D */
                        insn->type = insn_fsgnjx_d;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x14:
                {
                    u32 funct3 = FUNCT3(data);

                    switch (funct3)
                    {
                    case 0x0: /* FMIN.S */
                        insn->type = insn_fmin_s;
                        return;
                    case 0x1: /* FMAX.S */
                        insn->type = insn_fmax_s;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x15:
                {
                    u32 funct3 = FUNCT3(data);

                    switch (funct3)
                    {
                    case 0x0: /* FMIN.D */
                        insn->type = insn_fmin_d;
                        return;
                    case 0x1: /* FMAX.D */
                        insn->type = insn_fmax_d;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x20: /* FCVT.S.D */
                    assert(static_cast<i8>(RS2(data)) == 1);
                    insn->type = insn_fcvt_s_d;
                    return;
                case 0x21: /* FCVT.D.S */
                    assert(static_cast<i8>(RS2(data)) == 0);
                    insn->type = insn_fcvt_d_s;
                    return;
                case 0x2c: /* FSQRT.S */
                    assert(insn->rs2 == 0);
                    insn->type = insn_fsqrt_s;
                    return;
                case 0x2d: /* FSQRT.D */
                    assert(insn->rs2 == 0);
                    insn->type = insn_fsqrt_d;
                    return;
                case 0x50:
                {
                    u32 funct3 = FUNCT3(data);

                    switch (funct3)
                    {
                    case 0x0: /* FLE.S */
                        insn->type = insn_fle_s;
                        return;
                    case 0x1: /* FLT.S */
                        insn->type = insn_flt_s;
                        return;
                    case 0x2: /* FEQ.S */
                        insn->type = insn_feq_s;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x51:
                {
                    u32 funct3 = FUNCT3(data);

                    switch (funct3)
                    {
                    case 0x0: /* FLE.D */
                        insn->type = insn_fle_d;
                        return;
                    case 0x1: /* FLT.D */
                        insn->type = insn_flt_d;
                        return;
                    case 0x2: /* FEQ.D */
                        insn->type = insn_feq_d;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x60:
                {
                    u32 rs2 = static_cast<i8>(RS2(data));

                    switch (rs2)
                    {
                    case 0x0: /* FCVT.W.S */
                        insn->type = insn_fcvt_w_s;
                        return;
                    case 0x1: /* FCVT.WU.S */
                        insn->type = insn_fcvt_wu_s;
                        return;
                    case 0x2: /* FCVT.L.S */
                        insn->type = insn_fcvt_l_s;
                        return;
                    case 0x3: /* FCVT.LU.S */
                        insn->type = insn_fcvt_lu_s;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x61:
                {
                    u32 rs2 = static_cast<i8>(RS2(data));

                    switch (rs2)
                    {
                    case 0x0: /* FCVT.W.D */
                        insn->type = insn_fcvt_w_d;
                        return;
                    case 0x1: /* FCVT.WU.D */
                        insn->type = insn_fcvt_wu_d;
                        return;
                    case 0x2: /* FCVT.L.D */
                        insn->type = insn_fcvt_l_d;
                        return;
                    case 0x3: /* FCVT.LU.D */
                        insn->type = insn_fcvt_lu_d;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x68:
                {
                    u32 rs2 = static_cast<i8>(RS2(data));

                    switch (rs2)
                    {
                    case 0x0: /* FCVT.S.W */
                        insn->type = insn_fcvt_s_w;
                        return;
                    case 0x1: /* FCVT.S.WU */
                        insn->type = insn_fcvt_s_wu;
                        return;
                    case 0x2: /* FCVT.S.L */
                        insn->type = insn_fcvt_s_l;
                        return;
                    case 0x3: /* FCVT.S.LU */
                        insn->type = insn_fcvt_s_lu;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x69:
                {
                    u32 rs2 = static_cast<i8>(RS2(data));

                    switch (rs2)
                    {
                    case 0x0: /* FCVT.D.W */
                        insn->type = insn_fcvt_d_w;
                        return;
                    case 0x1: /* FCVT.D.WU */
                        insn->type = insn_fcvt_d_wu;
                        return;
                    case 0x2: /* FCVT.D.L */
                        insn->type = insn_fcvt_d_l;
                        return;
                    case 0x3: /* FCVT.D.LU */
                        insn->type = insn_fcvt_d_lu;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x70:
                {
                    assert(static_cast<i8>(RS2(data)) == 0);
                    u32 funct3 = FUNCT3(data);

                    switch (funct3)
                    {
                    case 0x0: /* FMV.X.W */
                        insn->type = insn_fmv_x_w;
                        return;
                    case 0x1: /* FCLASS.S */
                        insn->type = insn_fclass_s;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x71:
                {
                    assert(static_cast<i8>(RS2(data)) == 0);
                    u32 funct3 = FUNCT3(data);

                    switch (funct3)
                    {
                    case 0x0: /* FMV.X.D */
                        insn->type = insn_fmv_x_d;
                        return;
                    case 0x1: /* FCLASS.D */
                        insn->type = insn_fclass_d;
                        return;
                    default:
                        unreachable();
                    }
                }
                    unreachable();
                case 0x78: /* FMV_W_X */
                    assert(static_cast<i8>(RS2(data)) == 0 && FUNCT3(data) == 0);
                    insn->type = insn_fmv_w_x;
                    return;
                case 0x79: /* FMV_D_X */
                    assert(static_cast<i8>(RS2(data)) == 0 && FUNCT3(data) == 0);
                    insn->type = insn_fmv_d_x;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x18:
            {
                *insn = insn_btype_read(data);

                u32 funct3 = FUNCT3(data);
                switch (funct3)
                {
                case 0x0: /* BEQ */
                    insn->type = insn_beq;
                    return;
                case 0x1: /* BNE */
                    insn->type = insn_bne;
                    return;
                case 0x4: /* BLT */
                    insn->type = insn_blt;
                    return;
                case 0x5: /* BGE */
                    insn->type = insn_bge;
                    return;
                case 0x6: /* BLTU */
                    insn->type = insn_bltu;
                    return;
                case 0x7: /* BGEU */
                    insn->type = insn_bgeu;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            case 0x19: /* JALR */
                *insn = insn_itype_read(data);
                insn->type = insn_jalr;
                insn->cont = true;
                return;
            case 0x1b: /* JAL */
                *insn = insn_jtype_read(data);
                insn->type = insn_jal;
                insn->cont = true;
                return;
            case 0x1c:
            {
                if (data == 0x73)
                { /* ECALL */
                    insn->type = insn_ecall;
                    insn->cont = true;
                    return;
                }

                u32 funct3 = FUNCT3(data);
                *insn = insn_csrtype_read(data);
                switch (funct3)
                {
                case 0x1: /* CSRRW */
                    insn->type = insn_csrrw;
                    return;
                case 0x2: /* CSRRS */
                    insn->type = insn_csrrs;
                    return;
                case 0x3: /* CSRRC */
                    insn->type = insn_csrrc;
                    return;
                case 0x5: /* CSRRWI */
                    insn->type = insn_csrrwi;
                    return;
                case 0x6: /* CSRRSI */
                    insn->type = insn_csrrsi;
                    return;
                case 0x7: /* CSRRCI */
                    insn->type = insn_csrrci;
                    return;
                default:
                    unreachable();
                }
            }
                unreachable();
            default:
                unreachable();
            }
        }
            unreachable();
        default:
            unreachable();
        }
    }
};




#endif // EMULATOR_DECORDER_HPP