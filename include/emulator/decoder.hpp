/// \file emulator/decord.hpp
/// \brief RISC-V64 decord 模拟

#ifndef EMULATOR_DECORDER_HPP
#define EMULATOR_DECORDER_HPP


#include "emulator/trap.hpp"

// ==================================================================================== //
// decord
// ==================================================================================== //



u64 imm_u(u32 inst) {return SEXT(BITS(inst, 31, 12), 20);}
u64 imm_j(u32 inst) {return (SEXT(BITS(inst, 31, 31), 1) << 20) | (BITS(inst, 30, 21) << 1) | (BITS(inst, 20, 20) << 11) | (BITS(inst, 19, 12) << 12);}
u64 imm_i(u32 inst) {return SEXT(BITS(inst, 31, 20), 12);}
u64 imm_s(u32 inst) {return SEXT((BITS(inst, 31, 25) << 5) | BITS(inst, 11, 7), 12); }
u64 imm_b(u32 inst) {return (SEXT(BITS(inst, 31, 31), 1) << 12) | (BITS(inst, 30, 25) << 5) | (BITS(inst, 11, 8) << 1) | (BITS(inst, 7, 7) << 11);}

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
    } inst_name;

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
    CPU cpu;


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
            printf("imm_s == 0x%llx\n", this->imm);
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

    void (decoder::*inst_handle[INST_NUM])(CPU &host_cpu);

    void set_inst_func(enum INST_NAME inst_name, void (decoder::*fp)(CPU &host_cpu))
    {
        inst_handle[inst_name] = fp;
    }

    void lui(CPU &host_cpu)
    {
        printf("lui this->imm = %llx\n", this->imm);
        this->cpu.regs[this->rd] = this->imm << 12;
        printf("lui this->imm << 12 = %llx\n", this->cpu.regs[this->rd]);
    }

    void auipc(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.pc + (this->imm << 12);
    }

    void jal(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->snpc;
        this->dnpc = this->imm + this->cpu.pc;
    }

    void jalr(CPU &host_cpu)
    {
        this->dnpc = (this->cpu.regs[this->rs1] + this->imm) & ~1;
        this->cpu.regs[this->rd] = this->snpc;
    }

    void beq(CPU &host_cpu)
    {
        if (this->cpu.regs[this->rs1] == this->cpu.regs[this->rs2])
        {
            printf("beq offset = 0x%lx\n", (unsigned long)this->imm);
            this->dnpc = this->cpu.pc + this->imm;
        }
    }

    void bne(CPU &host_cpu)
    {
        if (this->cpu.regs[this->rs1] != this->cpu.regs[this->rs2])
        {
            printf("bne offset = 0x%lx, rs1 = 0x%lx, rs2 = 0x%lx\n", (unsigned long)this->imm, (unsigned long)this->cpu.regs[this->rs1], (unsigned long)this->cpu.regs[this->rs2]);
            this->dnpc = this->cpu.pc + this->imm;
        }
    }

    void blt(CPU &host_cpu)
    {
        if ((long long)this->cpu.regs[this->rs1] < (long long)this->cpu.regs[this->rs2])
        {
            this->dnpc = this->cpu.pc + this->imm;
        }
    }

    void bge(CPU &host_cpu)
    {
        if ((long long)this->cpu.regs[this->rs1] >= (long long)this->cpu.regs[this->rs2])
        {
            this->dnpc = this->cpu.pc + this->imm;
        }
    }

    void bltu(CPU &host_cpu)
    {
        if (this->cpu.regs[this->rs1] < this->cpu.regs[this->rs2])
        {
            this->dnpc = this->cpu.pc + this->imm;
        }
    }

    void bgeu(CPU &host_cpu)
    {
        if (this->cpu.regs[this->rs1] >= this->cpu.regs[this->rs2])
        {
            this->dnpc = this->cpu.pc + this->imm;
        }
    }

    void lb(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(this->cpu.cpu_load(this->cpu.regs[this->rs1] + this->imm, 1), 8);
    }

    void lh(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(this->cpu.cpu_load(this->cpu.regs[this->rs1] + this->imm, 2), 16);
    }

    void lw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(this->cpu.cpu_load(this->cpu.regs[this->rs1] + this->imm, 4), 32);
    }

    void lbu(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.cpu_load(this->cpu.regs[this->rs1] + this->imm, 1);
    }

    void lhu(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.cpu_load(this->cpu.regs[this->rs1] + this->imm, 2);
    }

    void lwu(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.cpu_load(this->cpu.regs[this->rs1] + this->imm, 4);
    }

    void ld(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.cpu_load(this->cpu.regs[this->rs1] + this->imm, 8);
    }

    void sb(CPU &host_cpu)
    {
        this->cpu.cpu_store(this->cpu.regs[this->rs1] + this->imm, 1, this->cpu.regs[this->rs2]);
    }

    void sh(CPU &host_cpu)
    {
        this->cpu.cpu_store(this->cpu.regs[this->rs1] + this->imm, 2, this->cpu.regs[this->rs2]);
    }

    void sw(CPU &host_cpu)
    {
        this->cpu.cpu_store(this->cpu.regs[this->rs1] + this->imm, 4, this->cpu.regs[this->rs2]);
    }

    void sd(CPU &host_cpu)
    {
        printf("sd addr = 0x%llx\n", this->cpu.regs[this->rs1] + this->imm);
        this->cpu.cpu_store(this->cpu.regs[this->rs1] + this->imm, 8, this->cpu.regs[this->rs2]);
    }

    void addi(CPU &host_cpu)
    {
        printf("addi rd = %d x[rs1 = %d] = 0x%lx imm = 0x%lx\n", this->rd, this->rs1, (unsigned long)this->cpu.regs[this->rs1], (unsigned long)this->imm);
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] + this->imm;
    }

    void slti(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = (long long)this->cpu.regs[this->rs1] < (long long)this->imm ? 1 : 0;
    }

    void sltiu(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] < this->imm ? 1 : 0;
    }

    void xori(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] ^ this->imm;
    }

    void ori(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] | this->imm;
    }

    void andi(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] & this->imm;
    }

    void slli(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] << this->shamt;
    }

    void srli(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] >> this->shamt;
    }

    void srai(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = ((long long)this->cpu.regs[this->rs1]) >> this->shamt;
    }

    void add(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] + this->cpu.regs[this->rs2];
    }

    void sub(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] - this->cpu.regs[this->rs2];
    }

    void sll(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] << BITS(this->cpu.regs[this->rs2], 5, 0);
    }

    void slt(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = (long long)this->cpu.regs[this->rs1] < (long long)this->cpu.regs[this->rs2] ? 1 : 0;
    }

    void sltu(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] < this->cpu.regs[this->rs2] ? 1 : 0;
    }

    void xor_f(CPU &host_cpu) 
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] ^ this->cpu.regs[this->rs2];
    }

    void srl(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] >> BITS(this->cpu.regs[this->rs2], 5, 0);
    }

    void sra(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = ((long long)this->cpu.regs[this->rs1]) >> BITS(this->cpu.regs[this->rs2], 5, 0);
    }

    void or_f(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] | this->cpu.regs[this->rs2];
    }

    void and_f(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = this->cpu.regs[this->rs1] & this->cpu.regs[this->rs2];
    }

    void fence(CPU &host_cpu)
    {
        // todo
        return;
    }

    void trap_handler(CPU host_cpu, enum TRAP traptype, bool isException, u64 cause, u64 tval)
    {
        if (traptype == Fatal)
        {
            this->cpu.state = CPU::CPU_STOP;
            return;
        }
        enum CPU::CPU_PRI_LEVEL nxt_level = CPU::M;
        if (this->cpu.pri_level <= CPU::S)
        {
            if ((isException && (host_cpu.get_csr(medeleg) & (1 << cause))) || (!isException && (host_cpu.get_csr(mideleg) & (1 << cause))))
            {
                nxt_level = CPU::S;
            }
        }
        if (nxt_level == CPU::S)
        {
            host_cpu.set_xpp(CPU::S, cpu.pri_level);
            host_cpu.set_xpie(CPU::S, host_cpu.get_xie(CPU::S));
            host_cpu.set_xie(CPU::S, 0);
            host_cpu.set_csr(sepc, cpu.pc);
            host_cpu.set_csr(stval, tval);
            host_cpu.set_csr(scause, ((isException ? 0ull : 1ull) << 63) | cause);
            u64 tvec = host_cpu.get_csr(stvec);
            this->dnpc = (BITS(tvec, 63, 2) << 2) + (BITS(tvec, 1, 0) == 1 ? cause * 4 : 0);
        }
        else
        {
            host_cpu.set_xpp(CPU::M, cpu.pri_level);
            host_cpu.set_xpie(CPU::M, host_cpu.get_xie(CPU::M));
            host_cpu.set_xie(CPU::M, 0);
            host_cpu.set_csr(mepc, cpu.pc);
            host_cpu.set_csr(mtval, tval);
            host_cpu.set_csr(mcause, ((isException ? 0ull : 1ull) << 63) | cause);
            u64 tvec = host_cpu.get_csr(mtvec);
            this->dnpc = (BITS(tvec, 63, 2) << 2) + (BITS(tvec, 1, 0) == 1 ? cause * 4 : 0);
        }
        cpu.pri_level = nxt_level;
    }

    void ecall(CPU &host_cpu)
    {
        if (riscv_tests && this->cpu.regs[CPU::a7] == 93)
        {
            if (this->cpu.regs[CPU::a0] == 0)
            {
                printf("Test Pass\n");
                this->cpu.state = CPU::CPU_STOP;
            }
            else
            {
                printf("Test #%d Fail\n", (int)this->cpu.regs[CPU::a0] / 2);
                this->cpu.state = CPU::CPU_STOP;
            }
        }
        todo("trap_handler");
        trap_handler(host_cpu, Requested, false, this->cpu.pri_level + 8, 0);
        return;
    }

    void ebreak(CPU &host_cpu)
    {
        // todo
        exit(0);
        return;
    }

    void addiw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(BITS(this->cpu.regs[this->rs1] + this->imm, 31, 0), 32);
    }

    void slliw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(BITS(this->cpu.regs[this->rs1] << this->shamt, 31, 0), 32);
    }

    void srliw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(BITS(this->cpu.regs[this->rs1], 31, 0) >> this->shamt, 32);
    }

    void sraiw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(((int)BITS(this->cpu.regs[this->rs1], 31, 0)) >> this->shamt, 32);
    }

    void addw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(BITS(this->cpu.regs[this->rs1] + this->cpu.regs[this->rs2], 31, 0), 32);
    }

    void subw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(this->cpu.regs[this->rs1] - this->cpu.regs[this->rs2], 32);
    }

    void sllw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(BITS(this->cpu.regs[this->rs1] << BITS(this->cpu.regs[this->rs2], 4, 0), 31, 0), 32);
    }

    void srlw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT(BITS(this->cpu.regs[this->rs1], 31, 0) >> BITS(this->cpu.regs[this->rs2], 4, 0), 32);
    }

    void sraw(CPU &host_cpu)
    {
        this->cpu.regs[this->rd] = SEXT((int)BITS(this->cpu.regs[this->rs1], 31, 0) >> BITS(this->cpu.regs[this->rs2], 4, 0), 32);
    }

    // Zicsr
    void csrrw(CPU &host_cpu)
    {
        u64 csrval;
        if (this->rd != 0)
            csrval = this->cpu.csr.csr[this->csr_addr];
        else
            csrval = 0;
        u64 rs1val = this->cpu.regs[this->rs1];
        printf("csrval = 0x%08lx, rs1val = 0x%08lx\n", (unsigned long)csrval, (unsigned long)rs1val);
        this->cpu.regs[this->rd] = csrval;
        this->cpu.csr.csr[this->csr_addr] = rs1val;
    }

    void csrrs(CPU &host_cpu)
    {
        u64 csrval = this->cpu.csr.csr[this->csr_addr];
        u64 rs1val = this->rs1 == 0 ? 0 : this->cpu.regs[this->rs1];
        printf("before csrval = 0x%08lx, rs1val = 0x%08lx\n", (unsigned long)csrval, (unsigned long)rs1val);
        this->cpu.regs[this->rd] = csrval;
        if (this->rs1 != 0)
            this->cpu.csr.csr[this->csr_addr] = csrval | rs1val;
        printf("after csrval = 0x%08lx, rs1val = 0x%08lx\n", (unsigned long)this->cpu.csr.csr[this->csr_addr], (unsigned long)rs1val);
    }

    void csrrc(CPU &host_cpu)
    {
        u64 csrval = this->cpu.csr.csr[this->csr_addr];
        u64 rs1val = this->rs1 == 0 ? 0 : this->cpu.regs[this->rs1];
        this->cpu.regs[this->rd] = csrval;
        rs1val = ~rs1val;
        if (this->rs1 != 0)
            this->cpu.csr.csr[this->csr_addr] = csrval & rs1val;
    }

    void csrrwi(CPU &host_cpu)
    {
        u64 uimm = this->rs1;
        u64 csrval = this->rd == 0 ? 0 : this->cpu.csr.csr[this->csr_addr];
        this->cpu.regs[this->rd] = csrval;
        this->cpu.csr.csr[this->csr_addr] = uimm;
    }

    void csrrsi(CPU &host_cpu)
    {
        u64 uimm = this->rs1;
        u64 csrval = this->cpu.csr.csr[this->csr_addr];
        this->cpu.regs[this->rd] = csrval;
        this->cpu.csr.csr[this->csr_addr] = csrval | uimm;
    }

    void csrrci(CPU &host_cpu)
    {
        u64 uimm = this->rs1;
        u64 csrval = this->cpu.csr.csr[this->csr_addr];
        this->cpu.regs[this->rd] = csrval;
        uimm = ~uimm;
        this->cpu.csr.csr[this->csr_addr] = csrval & uimm;
    }

    // trap return inst
    void mret(CPU &host_cpu)
    {
        int pre_level = host_cpu.get_xpp(CPU::M);
        host_cpu.set_xie(CPU::M, host_cpu.get_xpie(CPU::M));
        host_cpu.set_xpie(CPU::M, 1);
        host_cpu.set_xpp(CPU::M, CPU::U);
        host_cpu.set_csr(mstatus, host_cpu.get_csr(mstatus) & (~(1 << 17)));
        this->dnpc = host_cpu.get_csr(mepc);
        this->cpu.pri_level = CPU::cast_to_pre_level(pre_level);
    }

    void sret(CPU &host_cpu)
    {
        int pre_level = host_cpu.get_xpp(CPU::S);
        host_cpu.set_xie(CPU::S, host_cpu.get_xpie(CPU::S));
        host_cpu.set_xpie(CPU::S, 1);
        host_cpu.set_xpp(CPU::S, CPU::U);
        host_cpu.set_csr(sstatus, host_cpu.get_csr(sstatus) & (~(1 << 17)));
        this->dnpc = host_cpu.get_csr(sepc);
        this->cpu.pri_level = CPU::cast_to_pre_level(pre_level);
    }

    void init_inst_func()
    {
        set_inst_func(LUI, &decoder::lui);
        set_inst_func(AUIPC, &decoder::auipc);
        set_inst_func(JAL, &decoder::jal);
        set_inst_func(JALR, &decoder::jalr);
        set_inst_func(BEQ, &decoder::beq);
        set_inst_func(BNE, &decoder::bne);
        set_inst_func(BLT, &decoder::blt);
        set_inst_func(BGE, &decoder::bge);
        set_inst_func(BLTU, &decoder::bltu);
        set_inst_func(BGEU, &decoder::bgeu);
        set_inst_func(LB, &decoder::lb);
        set_inst_func(LH, &decoder::lh);
        set_inst_func(LW, &decoder::lw);
        set_inst_func(LBU, &decoder::lbu);
        set_inst_func(LHU, &decoder::lhu);
        set_inst_func(SB, &decoder::sb);
        set_inst_func(SH, &decoder::sh);
        set_inst_func(SW, &decoder::sw);
        set_inst_func(ADDI, &decoder::addi);
        set_inst_func(SLTI, &decoder::slti);
        set_inst_func(SLTIU, &decoder::sltiu);
        set_inst_func(XORI, &decoder::xori);
        set_inst_func(ORI, &decoder::ori);
        set_inst_func(ANDI, &decoder::andi);
        set_inst_func(SLLI, &decoder::slli);
        set_inst_func(SRLI, &decoder::srli);
        set_inst_func(SRAI, &decoder::srai);
        set_inst_func(ADD, &decoder::add);
        set_inst_func(SUB, &decoder::sub);
        set_inst_func(SLL, &decoder::sll);
        set_inst_func(SLT, &decoder::slt);
        set_inst_func(SLTU, &decoder::sltu);
        set_inst_func(XOR, &decoder::xor_f);
        set_inst_func(SRL, &decoder::srl);
        set_inst_func(SRA, &decoder::sra);
        set_inst_func(OR, &decoder::or_f);
        set_inst_func(AND, &decoder::and_f);
        set_inst_func(FENCE, &decoder::fence);
        set_inst_func(ECALL, &decoder::ecall);
        set_inst_func(EBREAK, &decoder::ebreak);
        set_inst_func(LWU, &decoder::lwu);
        set_inst_func(LD, &decoder::ld);
        set_inst_func(SD, &decoder::sd);
        set_inst_func(ADDIW, &decoder::addiw);
        set_inst_func(SLLIW, &decoder::slliw);
        set_inst_func(SRLIW, &decoder::srliw);
        set_inst_func(SRAIW, &decoder::sraiw);
        set_inst_func(ADDW, &decoder::addw);
        set_inst_func(SUBW, &decoder::subw);
        set_inst_func(SLLW, &decoder::sllw);
        set_inst_func(SRLW, &decoder::srlw);
        set_inst_func(SRAW, &decoder::sraw);

        // Zicsr
        set_inst_func(CSRRW, &decoder::csrrw);
        set_inst_func(CSRRS, &decoder::csrrs);
        set_inst_func(CSRRC, &decoder::csrrc);
        set_inst_func(CSRRWI, &decoder::csrrwi);
        set_inst_func(CSRRSI, &decoder::csrrsi);
        set_inst_func(CSRRCI, &decoder::csrrci);

        // mret & sret
        set_inst_func(MRET, &decoder::mret);
        set_inst_func(SRET, &decoder::sret);
    }

    void exec_inst(CPU &host_cpu)
    {
        (this->*inst_handle[this->inst_name])(host_cpu);
    }
};




#endif // EMULATOR_DECORDER_HPP