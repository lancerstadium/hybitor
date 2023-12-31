/**
 * @file include/capstone2llvmir/mips/mips_init.cpp
 * @brief Initializations for MIPS implementation of @c Capstone2LlvmIrTranslator.
 */

#include "capstone2llvmir/mips/mips_impl.h"


namespace capstone2llvmir {

//
//==============================================================================
// Pure virtual methods from Capstone2LlvmIrTranslator_impl
//==============================================================================
//

void Capstone2LlvmIrTranslatorMips_impl::initializeArchSpecific()
{
	// Nothing.
}

void Capstone2LlvmIrTranslatorMips_impl::initializeRegNameMap()
{
	std::map<uint32_t, std::string> r2n =
	{
			// mips_reg_fpu_double
			//
			{MIPS_REG_FD0, "fd0"},
			{MIPS_REG_FD2, "fd2"},
			{MIPS_REG_FD4, "fd4"},
			{MIPS_REG_FD6, "fd6"},
			{MIPS_REG_FD8, "fd8"},
			{MIPS_REG_FD10, "fd10"},
			{MIPS_REG_FD12, "fd12"},
			{MIPS_REG_FD14, "fd14"},
			{MIPS_REG_FD16, "fd16"},
			{MIPS_REG_FD18, "fd18"},
			{MIPS_REG_FD20, "fd20"},
			{MIPS_REG_FD22, "fd22"},
			{MIPS_REG_FD24, "fd24"},
			{MIPS_REG_FD26, "fd26"},
			{MIPS_REG_FD28, "fd28"},
			{MIPS_REG_FD30, "fd30"},
	};

	_reg2name = std::move(r2n);
}

void Capstone2LlvmIrTranslatorMips_impl::initializeRegTypeMap()
{
	auto* i1 = llvm::IntegerType::getInt32Ty(_module->getContext());
	auto* i32 = llvm::IntegerType::getInt32Ty(_module->getContext());
	auto* i64 = llvm::IntegerType::getInt64Ty(_module->getContext());
	auto* i128 = llvm::IntegerType::getInt64Ty(_module->getContext());
	auto* f32 = llvm::Type::getFloatTy(_module->getContext());
	auto* f64 = llvm::Type::getDoubleTy(_module->getContext());
	auto* f128 = llvm::Type::getFP128Ty(_module->getContext());

	auto* defTy = _basicMode == CS_MODE_MIPS64 ? i64 : i32;
	auto* defFty = _basicMode == CS_MODE_MIPS64 ? f64 : f32;

	std::map<uint32_t, llvm::Type*> r2t =
	{
			// Program counter.
			//
			{MIPS_REG_PC, defTy},

			// General purpose registers.
			//
			{MIPS_REG_0, defTy},
			{MIPS_REG_1, defTy},
			{MIPS_REG_2, defTy},
			{MIPS_REG_3, defTy},
			{MIPS_REG_4, defTy},
			{MIPS_REG_5, defTy},
			{MIPS_REG_6, defTy},
			{MIPS_REG_7, defTy},
			{MIPS_REG_8, defTy},
			{MIPS_REG_9, defTy},
			{MIPS_REG_10, defTy},
			{MIPS_REG_11, defTy},
			{MIPS_REG_12, defTy},
			{MIPS_REG_13, defTy},
			{MIPS_REG_14, defTy},
			{MIPS_REG_15, defTy},
			{MIPS_REG_16, defTy},
			{MIPS_REG_17, defTy},
			{MIPS_REG_18, defTy},
			{MIPS_REG_19, defTy},
			{MIPS_REG_20, defTy},
			{MIPS_REG_21, defTy},
			{MIPS_REG_22, defTy},
			{MIPS_REG_23, defTy},
			{MIPS_REG_24, defTy},
			{MIPS_REG_25, defTy},
			{MIPS_REG_26, defTy},
			{MIPS_REG_27, defTy},
			{MIPS_REG_28, defTy},
			{MIPS_REG_29, defTy},
			{MIPS_REG_30, defTy},
			{MIPS_REG_31, defTy},

			// DSP registers.
			//
			{MIPS_REG_DSPCCOND, i1},
			{MIPS_REG_DSPCARRY, i1},
			{MIPS_REG_DSPEFI, i1},
			{MIPS_REG_DSPOUTFLAG, i1},
			{MIPS_REG_DSPOUTFLAG16_19, i1},
			{MIPS_REG_DSPOUTFLAG20, i1},
			{MIPS_REG_DSPOUTFLAG21, i1},
			{MIPS_REG_DSPOUTFLAG22, i1},
			{MIPS_REG_DSPOUTFLAG23, i1},
			{MIPS_REG_DSPPOS, defTy},
			{MIPS_REG_DSPSCOUNT, defTy},

			// ACC registers.
			//
			{MIPS_REG_AC0, defTy},
			{MIPS_REG_AC1, defTy},
			{MIPS_REG_AC2, defTy},
			{MIPS_REG_AC3, defTy},

			// COP registers.
			//
			{MIPS_REG_CC0, defTy},
			{MIPS_REG_CC1, defTy},
			{MIPS_REG_CC2, defTy},
			{MIPS_REG_CC3, defTy},
			{MIPS_REG_CC4, defTy},
			{MIPS_REG_CC5, defTy},
			{MIPS_REG_CC6, defTy},
			{MIPS_REG_CC7, defTy},

			// FPU registers.
			//
			{MIPS_REG_F0, defFty},
			{MIPS_REG_F1, defFty},
			{MIPS_REG_F2, defFty},
			{MIPS_REG_F3, defFty},
			{MIPS_REG_F4, defFty},
			{MIPS_REG_F5, defFty},
			{MIPS_REG_F6, defFty},
			{MIPS_REG_F7, defFty},
			{MIPS_REG_F8, defFty},
			{MIPS_REG_F9, defFty},
			{MIPS_REG_F10, defFty},
			{MIPS_REG_F11, defFty},
			{MIPS_REG_F12, defFty},
			{MIPS_REG_F13, defFty},
			{MIPS_REG_F14, defFty},
			{MIPS_REG_F15, defFty},
			{MIPS_REG_F16, defFty},
			{MIPS_REG_F17, defFty},
			{MIPS_REG_F18, defFty},
			{MIPS_REG_F19, defFty},
			{MIPS_REG_F20, defFty},
			{MIPS_REG_F21, defFty},
			{MIPS_REG_F22, defFty},
			{MIPS_REG_F23, defFty},
			{MIPS_REG_F24, defFty},
			{MIPS_REG_F25, defFty},
			{MIPS_REG_F26, defFty},
			{MIPS_REG_F27, defFty},
			{MIPS_REG_F28, defFty},
			{MIPS_REG_F29, defFty},
			{MIPS_REG_F30, defFty},
			{MIPS_REG_F31, defFty},

			{MIPS_REG_FCC0, defTy},
			{MIPS_REG_FCC1, defTy},
			{MIPS_REG_FCC2, defTy},
			{MIPS_REG_FCC3, defTy},
			{MIPS_REG_FCC4, defTy},
			{MIPS_REG_FCC5, defTy},
			{MIPS_REG_FCC6, defTy},
			{MIPS_REG_FCC7, defTy},

			// AFPR128.
			//
			{MIPS_REG_W0, i128},
			{MIPS_REG_W1, i128},
			{MIPS_REG_W2, i128},
			{MIPS_REG_W3, i128},
			{MIPS_REG_W4, i128},
			{MIPS_REG_W5, i128},
			{MIPS_REG_W6, i128},
			{MIPS_REG_W7, i128},
			{MIPS_REG_W8, i128},
			{MIPS_REG_W9, i128},
			{MIPS_REG_W10, i128},
			{MIPS_REG_W11, i128},
			{MIPS_REG_W12, i128},
			{MIPS_REG_W13, i128},
			{MIPS_REG_W14, i128},
			{MIPS_REG_W15, i128},
			{MIPS_REG_W16, i128},
			{MIPS_REG_W17, i128},
			{MIPS_REG_W18, i128},
			{MIPS_REG_W19, i128},
			{MIPS_REG_W20, i128},
			{MIPS_REG_W21, i128},
			{MIPS_REG_W22, i128},
			{MIPS_REG_W23, i128},
			{MIPS_REG_W24, i128},
			{MIPS_REG_W25, i128},
			{MIPS_REG_W26, i128},
			{MIPS_REG_W27, i128},
			{MIPS_REG_W28, i128},
			{MIPS_REG_W29, i128},
			{MIPS_REG_W30, i128},
			{MIPS_REG_W31, f128},

			// Multiply and divide registers.
			//
			{MIPS_REG_HI, defTy},
			{MIPS_REG_LO, defTy},

			{MIPS_REG_P0, defTy},
			{MIPS_REG_P1, defTy},
			{MIPS_REG_P2, defTy},

			{MIPS_REG_MPL0, defTy},
			{MIPS_REG_MPL1, defTy},
			{MIPS_REG_MPL2, defTy},
	};

	// mips_reg_fpu_double
	//
	if (defFty->isFloatTy())
	{
		r2t.emplace(MIPS_REG_FD0, f64);
		r2t.emplace(MIPS_REG_FD2, f64);
		r2t.emplace(MIPS_REG_FD4, f64);
		r2t.emplace(MIPS_REG_FD6, f64);
		r2t.emplace(MIPS_REG_FD8, f64);
		r2t.emplace(MIPS_REG_FD10, f64);
		r2t.emplace(MIPS_REG_FD12, f64);
		r2t.emplace(MIPS_REG_FD14, f64);
		r2t.emplace(MIPS_REG_FD16, f64);
		r2t.emplace(MIPS_REG_FD18, f64);
		r2t.emplace(MIPS_REG_FD20, f64);
		r2t.emplace(MIPS_REG_FD22, f64);
		r2t.emplace(MIPS_REG_FD24, f64);
		r2t.emplace(MIPS_REG_FD26, f64);
		r2t.emplace(MIPS_REG_FD28, f64);
		r2t.emplace(MIPS_REG_FD30, f64);
	}

	_reg2type = std::move(r2t);
}

void Capstone2LlvmIrTranslatorMips_impl::initializePseudoCallInstructionIDs()
{
	_callInsnIds =
	{
			MIPS_INS_JAL,
			MIPS_INS_JALR,
			//
			MIPS_INS_BGEZAL,
			MIPS_INS_BGEZALL,
			MIPS_INS_BLTZAL,
			MIPS_INS_BLTZALL,
			//
			MIPS_INS_BAL,
	};

	_returnInsnIds =
	{
			// Nothing - MIPS returns via jump to return address register.
	};

	_branchInsnIds =
	{
			MIPS_INS_J,
			MIPS_INS_JR,
			MIPS_INS_B,
	};

	_condBranchInsnIds =
	{
			//
			MIPS_INS_BC1F,
			MIPS_INS_BC1FL,
			//
			MIPS_INS_BC1T,
			MIPS_INS_BC1TL,
			//
			MIPS_INS_BEQ,
			MIPS_INS_BEQL,
			MIPS_INS_BNE,
			MIPS_INS_BNEL,
			//
			MIPS_INS_BLEZ,
			MIPS_INS_BLEZL,
			MIPS_INS_BGTZ,
			MIPS_INS_BGTZL,
			MIPS_INS_BLTZ,
			MIPS_INS_BLTZL,
			MIPS_INS_BGEZ,
			MIPS_INS_BGEZL,
			MIPS_INS_BEQZ,
			MIPS_INS_BNEZ,
	};

	_controlFlowInsnIds =
	{
			// Currently, all instructions can be categorized based on their
			// IDs alone.
	};
}

//
//==============================================================================
// Instruction translation map initialization.
//==============================================================================
//

std::map<
	std::size_t,
	void (Capstone2LlvmIrTranslatorMips_impl::*)(
			cs_insn* i,
			cs_mips*,
			llvm::IRBuilder<>&)>
Capstone2LlvmIrTranslatorMips_impl::_i2fm =
{
		{MIPS_INS_INVALID, nullptr},

		{MIPS_INS_ABSQ_S, nullptr},
		{MIPS_INS_ADD, &Capstone2LlvmIrTranslatorMips_impl::translateAdd},
		{MIPS_INS_ADDIUPC, nullptr},
		{MIPS_INS_ADDIUR1SP, nullptr},
		{MIPS_INS_ADDIUR2, nullptr},
		{MIPS_INS_ADDIUS5, nullptr},
		{MIPS_INS_ADDIUSP, nullptr},
		{MIPS_INS_ADDQH, nullptr},
		{MIPS_INS_ADDQH_R, nullptr},
		{MIPS_INS_ADDQ, nullptr},
		{MIPS_INS_ADDQ_S, nullptr},
		{MIPS_INS_ADDSC, nullptr},
		{MIPS_INS_ADDS_A, nullptr},
		{MIPS_INS_ADDS_S, nullptr},
		{MIPS_INS_ADDS_U, nullptr},
		{MIPS_INS_ADDU16, nullptr},
		{MIPS_INS_ADDUH, nullptr},
		{MIPS_INS_ADDUH_R, nullptr},
		{MIPS_INS_ADDU, &Capstone2LlvmIrTranslatorMips_impl::translateAdd},
		{MIPS_INS_ADDU_S, nullptr},
		{MIPS_INS_ADDVI, nullptr},
		{MIPS_INS_ADDV, nullptr},
		{MIPS_INS_ADDWC, nullptr},
		{MIPS_INS_ADD_A, nullptr},
		{MIPS_INS_ADDI, &Capstone2LlvmIrTranslatorMips_impl::translateAdd},
		{MIPS_INS_ADDIU, &Capstone2LlvmIrTranslatorMips_impl::translateAdd},
		{MIPS_INS_ALIGN, nullptr},
		{MIPS_INS_ALUIPC, nullptr},
		{MIPS_INS_AND, &Capstone2LlvmIrTranslatorMips_impl::translateAnd},
		{MIPS_INS_AND16, nullptr},
		{MIPS_INS_ANDI16, nullptr},
		{MIPS_INS_ANDI, &Capstone2LlvmIrTranslatorMips_impl::translateAnd},
		{MIPS_INS_APPEND, nullptr},
		{MIPS_INS_ASUB_S, nullptr},
		{MIPS_INS_ASUB_U, nullptr},
		{MIPS_INS_AUI, nullptr},
		{MIPS_INS_AUIPC, nullptr},
		{MIPS_INS_AVER_S, nullptr},
		{MIPS_INS_AVER_U, nullptr},
		{MIPS_INS_AVE_S, nullptr},
		{MIPS_INS_AVE_U, nullptr},
		{MIPS_INS_B16, nullptr},
		{MIPS_INS_BADDU, nullptr},
		{MIPS_INS_BAL, &Capstone2LlvmIrTranslatorMips_impl::translateJal},
		{MIPS_INS_BALC, nullptr},
		{MIPS_INS_BALIGN, nullptr},
		{MIPS_INS_BBIT0, nullptr},
		{MIPS_INS_BBIT032, nullptr},
		{MIPS_INS_BBIT1, nullptr},
		{MIPS_INS_BBIT132, nullptr},
		{MIPS_INS_BC, nullptr},
		{MIPS_INS_BC0F, nullptr},
		{MIPS_INS_BC0FL, nullptr},
		{MIPS_INS_BC0T, nullptr},
		{MIPS_INS_BC0TL, nullptr},
		{MIPS_INS_BC1EQZ, nullptr},
		{MIPS_INS_BC1F, &Capstone2LlvmIrTranslatorMips_impl::translateBc1f},
		{MIPS_INS_BC1FL, &Capstone2LlvmIrTranslatorMips_impl::translateBc1f},
		{MIPS_INS_BC1NEZ, nullptr},
		{MIPS_INS_BC1T, &Capstone2LlvmIrTranslatorMips_impl::translateBc1t},
		{MIPS_INS_BC1TL, &Capstone2LlvmIrTranslatorMips_impl::translateBc1t},
		{MIPS_INS_BC2EQZ, nullptr},
		{MIPS_INS_BC2F, nullptr},
		{MIPS_INS_BC2FL, nullptr},
		{MIPS_INS_BC2NEZ, nullptr},
		{MIPS_INS_BC2T, nullptr},
		{MIPS_INS_BC2TL, nullptr},
		{MIPS_INS_BC3F, nullptr},
		{MIPS_INS_BC3FL, nullptr},
		{MIPS_INS_BC3T, nullptr},
		{MIPS_INS_BC3TL, nullptr},
		{MIPS_INS_BCLRI, nullptr},
		{MIPS_INS_BCLR, nullptr},
		{MIPS_INS_BEQ, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchTernary},
		{MIPS_INS_BEQC, nullptr},
		{MIPS_INS_BEQL, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchTernary},
		{MIPS_INS_BEQZ16, nullptr},
		{MIPS_INS_BEQZALC, nullptr},
		{MIPS_INS_BEQZC, nullptr},
		{MIPS_INS_BGEC, nullptr},
		{MIPS_INS_BGEUC, nullptr},
		{MIPS_INS_BGEZ, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BGEZAL, &Capstone2LlvmIrTranslatorMips_impl::translateBcondal},
		{MIPS_INS_BGEZALC, nullptr},
		{MIPS_INS_BGEZALL, &Capstone2LlvmIrTranslatorMips_impl::translateBcondal},
		{MIPS_INS_BGEZALS, nullptr},
		{MIPS_INS_BGEZC, nullptr},
		{MIPS_INS_BGEZL, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BGTZ, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BGTZALC, nullptr},
		{MIPS_INS_BGTZC, nullptr},
		{MIPS_INS_BGTZL, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BINSLI, nullptr},
		{MIPS_INS_BINSL, nullptr},
		{MIPS_INS_BINSRI, nullptr},
		{MIPS_INS_BINSR, nullptr},
		{MIPS_INS_BITREV, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_BITSWAP, nullptr},
		{MIPS_INS_BLEZ, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BLEZALC, nullptr},
		{MIPS_INS_BLEZC, nullptr},
		{MIPS_INS_BLEZL, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BLTC, nullptr},
		{MIPS_INS_BLTUC, nullptr},
		{MIPS_INS_BLTZ, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BLTZAL, &Capstone2LlvmIrTranslatorMips_impl::translateBcondal},
		{MIPS_INS_BLTZALC, nullptr},
		{MIPS_INS_BLTZALL, &Capstone2LlvmIrTranslatorMips_impl::translateBcondal},
		{MIPS_INS_BLTZALS, nullptr},
		{MIPS_INS_BLTZC, nullptr},
		{MIPS_INS_BLTZL, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BMNZI, nullptr},
		{MIPS_INS_BMNZ, nullptr},
		{MIPS_INS_BMZI, nullptr},
		{MIPS_INS_BMZ, nullptr},
		{MIPS_INS_BNE, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchTernary},
		{MIPS_INS_BNEC, nullptr},
		{MIPS_INS_BNEGI, nullptr},
		{MIPS_INS_BNEG, nullptr},
		{MIPS_INS_BNEL, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchTernary},
		{MIPS_INS_BNEZ16, nullptr},
		{MIPS_INS_BNEZALC, nullptr},
		{MIPS_INS_BNEZC, nullptr},
		{MIPS_INS_BNVC, nullptr},
		{MIPS_INS_BNZ, nullptr},
		{MIPS_INS_BOVC, nullptr},
		{MIPS_INS_BPOSGE32, nullptr},
		{MIPS_INS_BREAK, &Capstone2LlvmIrTranslatorMips_impl::translateBreak},
		{MIPS_INS_BREAK16, nullptr},
		{MIPS_INS_BSELI, nullptr},
		{MIPS_INS_BSEL, nullptr},
		{MIPS_INS_BSETI, nullptr},
		{MIPS_INS_BSET, nullptr},
		{MIPS_INS_BZ, nullptr},
		{MIPS_INS_BEQZ, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_B, &Capstone2LlvmIrTranslatorMips_impl::translateJ},
		{MIPS_INS_BNEZ, &Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary},
		{MIPS_INS_BTEQZ, nullptr},
		{MIPS_INS_BTNEZ, nullptr},
		{MIPS_INS_CACHE, nullptr},
		{MIPS_INS_CEIL, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_CEQI, nullptr},
		{MIPS_INS_CEQ, nullptr},
		{MIPS_INS_CFC1, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_CFCMSA, nullptr},
		{MIPS_INS_CINS, nullptr},
		{MIPS_INS_CINS32, nullptr},
		{MIPS_INS_CLASS, nullptr},
		{MIPS_INS_CLEI_S, nullptr},
		{MIPS_INS_CLEI_U, nullptr},
		{MIPS_INS_CLE_S, nullptr},
		{MIPS_INS_CLE_U, nullptr},
		{MIPS_INS_CLO, &Capstone2LlvmIrTranslatorMips_impl::translateClo},
		{MIPS_INS_CLTI_S, nullptr},
		{MIPS_INS_CLTI_U, nullptr},
		{MIPS_INS_CLT_S, nullptr},
		{MIPS_INS_CLT_U, nullptr},
		{MIPS_INS_CLZ, &Capstone2LlvmIrTranslatorMips_impl::translateClz},
		{MIPS_INS_CMPGDU, nullptr},
		{MIPS_INS_CMPGU, nullptr},
		{MIPS_INS_CMPU, nullptr},
		{MIPS_INS_CMP, nullptr},
		{MIPS_INS_COPY_S, nullptr},
		{MIPS_INS_COPY_U, nullptr},
		{MIPS_INS_CTC1, nullptr},
		{MIPS_INS_CTCMSA, nullptr},
		{MIPS_INS_CVT, &Capstone2LlvmIrTranslatorMips_impl::translateCvt},
		{MIPS_INS_C, &Capstone2LlvmIrTranslatorMips_impl::translateC},
		{MIPS_INS_CMPI, nullptr},
		{MIPS_INS_DADD, nullptr},
		{MIPS_INS_DADDI, nullptr},
		{MIPS_INS_DADDIU, nullptr},
		{MIPS_INS_DADDU, nullptr},
		{MIPS_INS_DAHI, nullptr},
		{MIPS_INS_DALIGN, nullptr},
		{MIPS_INS_DATI, nullptr},
		{MIPS_INS_DAUI, nullptr},
		{MIPS_INS_DBITSWAP, nullptr},
		{MIPS_INS_DCLO, nullptr},
		{MIPS_INS_DCLZ, nullptr},
		{MIPS_INS_DDIV, nullptr},
		{MIPS_INS_DDIVU, nullptr},
		{MIPS_INS_DERET, nullptr},
		{MIPS_INS_DEXT, nullptr},
		{MIPS_INS_DEXTM, nullptr},
		{MIPS_INS_DEXTU, nullptr},
		{MIPS_INS_DI, nullptr},
		{MIPS_INS_DINS, nullptr},
		{MIPS_INS_DINSM, nullptr},
		{MIPS_INS_DINSU, nullptr},
		{MIPS_INS_DIV, &Capstone2LlvmIrTranslatorMips_impl::translateDiv},
		{MIPS_INS_DIVU, &Capstone2LlvmIrTranslatorMips_impl::translateDivu},
		{MIPS_INS_DIV_S, nullptr},
		{MIPS_INS_DIV_U, nullptr},
		{MIPS_INS_DLSA, nullptr},
		{MIPS_INS_DMFC0, nullptr},
		{MIPS_INS_DMFC1, nullptr},
		{MIPS_INS_DMFC2, nullptr},
		{MIPS_INS_DMOD, nullptr},
		{MIPS_INS_DMODU, nullptr},
		{MIPS_INS_DMTC0, nullptr},
		{MIPS_INS_DMTC1, nullptr},
		{MIPS_INS_DMTC2, nullptr},
		{MIPS_INS_DMUH, nullptr},
		{MIPS_INS_DMUHU, nullptr},
		{MIPS_INS_DMUL, nullptr},
		{MIPS_INS_DMULT, nullptr},
		{MIPS_INS_DMULTU, nullptr},
		{MIPS_INS_DMULU, nullptr},
		{MIPS_INS_DOTP_S, nullptr},
		{MIPS_INS_DOTP_U, nullptr},
		{MIPS_INS_DPADD_S, nullptr},
		{MIPS_INS_DPADD_U, nullptr},
		{MIPS_INS_DPAQX_SA, nullptr},
		{MIPS_INS_DPAQX_S, nullptr},
		{MIPS_INS_DPAQ_SA, nullptr},
		{MIPS_INS_DPAQ_S, nullptr},
		{MIPS_INS_DPAU, nullptr},
		{MIPS_INS_DPAX, nullptr},
		{MIPS_INS_DPA, nullptr},
		{MIPS_INS_DPOP, nullptr},
		{MIPS_INS_DPSQX_SA, nullptr},
		{MIPS_INS_DPSQX_S, nullptr},
		{MIPS_INS_DPSQ_SA, nullptr},
		{MIPS_INS_DPSQ_S, nullptr},
		{MIPS_INS_DPSUB_S, nullptr},
		{MIPS_INS_DPSUB_U, nullptr},
		{MIPS_INS_DPSU, nullptr},
		{MIPS_INS_DPSX, nullptr},
		{MIPS_INS_DPS, nullptr},
		{MIPS_INS_DROTR, nullptr},
		{MIPS_INS_DROTR32, nullptr},
		{MIPS_INS_DROTRV, nullptr},
		{MIPS_INS_DSBH, nullptr},
		{MIPS_INS_DSHD, nullptr},
		{MIPS_INS_DSLL, nullptr},
		{MIPS_INS_DSLL32, nullptr},
		{MIPS_INS_DSLLV, nullptr},
		{MIPS_INS_DSRA, nullptr},
		{MIPS_INS_DSRA32, nullptr},
		{MIPS_INS_DSRAV, nullptr},
		{MIPS_INS_DSRL, nullptr},
		{MIPS_INS_DSRL32, nullptr},
		{MIPS_INS_DSRLV, nullptr},
		{MIPS_INS_DSUB, nullptr},
		{MIPS_INS_DSUBU, nullptr},
		{MIPS_INS_EHB, nullptr},
		{MIPS_INS_EI, nullptr},
		{MIPS_INS_ERET, nullptr},
		{MIPS_INS_EXT, &Capstone2LlvmIrTranslatorMips_impl::translateExt},
		{MIPS_INS_EXTP, nullptr},
		{MIPS_INS_EXTPDP, nullptr},
		{MIPS_INS_EXTPDPV, nullptr},
		{MIPS_INS_EXTPV, nullptr},
		{MIPS_INS_EXTRV_RS, nullptr},
		{MIPS_INS_EXTRV_R, nullptr},
		{MIPS_INS_EXTRV_S, nullptr},
		{MIPS_INS_EXTRV, nullptr},
		{MIPS_INS_EXTR_RS, nullptr},
		{MIPS_INS_EXTR_R, nullptr},
		{MIPS_INS_EXTR_S, nullptr},
		{MIPS_INS_EXTR, nullptr},
		{MIPS_INS_EXTS, nullptr},
		{MIPS_INS_EXTS32, nullptr},
		{MIPS_INS_ABS, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_FADD, nullptr},
		{MIPS_INS_FCAF, nullptr},
		{MIPS_INS_FCEQ, nullptr},
		{MIPS_INS_FCLASS, nullptr},
		{MIPS_INS_FCLE, nullptr},
		{MIPS_INS_FCLT, nullptr},
		{MIPS_INS_FCNE, nullptr},
		{MIPS_INS_FCOR, nullptr},
		{MIPS_INS_FCUEQ, nullptr},
		{MIPS_INS_FCULE, nullptr},
		{MIPS_INS_FCULT, nullptr},
		{MIPS_INS_FCUNE, nullptr},
		{MIPS_INS_FCUN, nullptr},
		{MIPS_INS_FDIV, nullptr},
		{MIPS_INS_FEXDO, nullptr},
		{MIPS_INS_FEXP2, nullptr},
		{MIPS_INS_FEXUPL, nullptr},
		{MIPS_INS_FEXUPR, nullptr},
		{MIPS_INS_FFINT_S, nullptr},
		{MIPS_INS_FFINT_U, nullptr},
		{MIPS_INS_FFQL, nullptr},
		{MIPS_INS_FFQR, nullptr},
		{MIPS_INS_FILL, nullptr},
		{MIPS_INS_FLOG2, nullptr},
		{MIPS_INS_FLOOR, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_FMADD, nullptr},
		{MIPS_INS_FMAX_A, nullptr},
		{MIPS_INS_FMAX, nullptr},
		{MIPS_INS_FMIN_A, nullptr},
		{MIPS_INS_FMIN, nullptr},
		{MIPS_INS_MOV, &Capstone2LlvmIrTranslatorMips_impl::translateMov},
		{MIPS_INS_FMSUB, nullptr},
		{MIPS_INS_FMUL, nullptr},
		{MIPS_INS_MUL, &Capstone2LlvmIrTranslatorMips_impl::translateMul},
		{MIPS_INS_NEG, &Capstone2LlvmIrTranslatorMips_impl::translateNeg},
		{MIPS_INS_FRCP, nullptr},
		{MIPS_INS_FRINT, nullptr},
		{MIPS_INS_FRSQRT, nullptr},
		{MIPS_INS_FSAF, nullptr},
		{MIPS_INS_FSEQ, nullptr},
		{MIPS_INS_FSLE, nullptr},
		{MIPS_INS_FSLT, nullptr},
		{MIPS_INS_FSNE, nullptr},
		{MIPS_INS_FSOR, nullptr},
		{MIPS_INS_FSQRT, nullptr},
		{MIPS_INS_SQRT, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_FSUB, nullptr},
		{MIPS_INS_SUB, &Capstone2LlvmIrTranslatorMips_impl::translateSub},
		{MIPS_INS_FSUEQ, nullptr},
		{MIPS_INS_FSULE, nullptr},
		{MIPS_INS_FSULT, nullptr},
		{MIPS_INS_FSUNE, nullptr},
		{MIPS_INS_FSUN, nullptr},
		{MIPS_INS_FTINT_S, nullptr},
		{MIPS_INS_FTINT_U, nullptr},
		{MIPS_INS_FTQ, nullptr},
		{MIPS_INS_FTRUNC_S, nullptr},
		{MIPS_INS_FTRUNC_U, nullptr},
		{MIPS_INS_HADD_S, nullptr},
		{MIPS_INS_HADD_U, nullptr},
		{MIPS_INS_HSUB_S, nullptr},
		{MIPS_INS_HSUB_U, nullptr},
		{MIPS_INS_ILVEV, nullptr},
		{MIPS_INS_ILVL, nullptr},
		{MIPS_INS_ILVOD, nullptr},
		{MIPS_INS_ILVR, nullptr},
		{MIPS_INS_INS, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{MIPS_INS_INSERT, nullptr},
		{MIPS_INS_INSV, nullptr},
		{MIPS_INS_INSVE, nullptr},
		{MIPS_INS_J, &Capstone2LlvmIrTranslatorMips_impl::translateJ},
		{MIPS_INS_JAL, &Capstone2LlvmIrTranslatorMips_impl::translateJal},
		{MIPS_INS_JALR, &Capstone2LlvmIrTranslatorMips_impl::translateJal},
		{MIPS_INS_JALRS16, nullptr},
		{MIPS_INS_JALRS, nullptr},
		{MIPS_INS_JALS, nullptr},
		{MIPS_INS_JALX, nullptr},
		{MIPS_INS_JIALC, nullptr},
		{MIPS_INS_JIC, nullptr},
		{MIPS_INS_JR, &Capstone2LlvmIrTranslatorMips_impl::translateJ},
		{MIPS_INS_JR16, nullptr},
		{MIPS_INS_JRADDIUSP, nullptr},
		{MIPS_INS_JRC, nullptr},
		{MIPS_INS_JALRC, nullptr},
		{MIPS_INS_LB, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LBU16, nullptr},
		{MIPS_INS_LBUX, nullptr},
		{MIPS_INS_LBU, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LD, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LDC1, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LDC2, nullptr},
		{MIPS_INS_LDC3, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LDI, nullptr},
		{MIPS_INS_LDL, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_LDPC, nullptr},
		{MIPS_INS_LDR, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_LDXC1, nullptr},
		{MIPS_INS_LH, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LHU16, nullptr},
		{MIPS_INS_LHX, nullptr},
		{MIPS_INS_LHU, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LI16, nullptr},
		{MIPS_INS_LL, nullptr},
		{MIPS_INS_LLD, nullptr},
		{MIPS_INS_LSA, nullptr},
		{MIPS_INS_LUXC1, nullptr},
		{MIPS_INS_LUI, &Capstone2LlvmIrTranslatorMips_impl::translateLui},
		{MIPS_INS_LW, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LW16, nullptr},
		{MIPS_INS_LWC1, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LWC2, nullptr},
		{MIPS_INS_LWC3, nullptr},
		{MIPS_INS_LWL, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_LWM16, nullptr},
		{MIPS_INS_LWM32, nullptr},
		{MIPS_INS_LWPC, nullptr},
		{MIPS_INS_LWP, nullptr},
		{MIPS_INS_LWR, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_LWUPC, nullptr},
		{MIPS_INS_LWU, &Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory},
		{MIPS_INS_LWX, nullptr},
		{MIPS_INS_LWXC1, nullptr},
		{MIPS_INS_LWXS, nullptr},
		{MIPS_INS_LI, nullptr},
		{MIPS_INS_MADD, &Capstone2LlvmIrTranslatorMips_impl::translateMadd},
		{MIPS_INS_MADDF, nullptr},
		{MIPS_INS_MADDR_Q, nullptr},
		{MIPS_INS_MADDU, &Capstone2LlvmIrTranslatorMips_impl::translateMadd},
		{MIPS_INS_MADDV, nullptr},
		{MIPS_INS_MADD_Q, nullptr},
		{MIPS_INS_MAQ_SA, nullptr},
		{MIPS_INS_MAQ_S, nullptr},
		{MIPS_INS_MAXA, nullptr},
		{MIPS_INS_MAXI_S, nullptr},
		{MIPS_INS_MAXI_U, nullptr},
		{MIPS_INS_MAX_A, nullptr},
		{MIPS_INS_MAX, &Capstone2LlvmIrTranslatorMips_impl::translateMax},
		{MIPS_INS_MAX_S, nullptr},
		{MIPS_INS_MAX_U, nullptr},
		{MIPS_INS_MFC0, nullptr},
		{MIPS_INS_MFC1, &Capstone2LlvmIrTranslatorMips_impl::translateMfc1},
		{MIPS_INS_MFC2, nullptr},
		{MIPS_INS_MFHC1, nullptr},
		{MIPS_INS_MFHI, &Capstone2LlvmIrTranslatorMips_impl::translateMfhi},
		{MIPS_INS_MFLO, &Capstone2LlvmIrTranslatorMips_impl::translateMflo},
		{MIPS_INS_MINA, nullptr},
		{MIPS_INS_MINI_S, nullptr},
		{MIPS_INS_MINI_U, nullptr},
		{MIPS_INS_MIN_A, nullptr},
		{MIPS_INS_MIN, &Capstone2LlvmIrTranslatorMips_impl::translateMin},
		{MIPS_INS_MIN_S, nullptr},
		{MIPS_INS_MIN_U, nullptr},
		{MIPS_INS_MOD, nullptr},
		{MIPS_INS_MODSUB, nullptr},
		{MIPS_INS_MODU, nullptr},
		{MIPS_INS_MOD_S, nullptr},
		{MIPS_INS_MOD_U, nullptr},
		{MIPS_INS_MOVE, &Capstone2LlvmIrTranslatorMips_impl::translateMov},
		{MIPS_INS_MOVEP, nullptr},
		{MIPS_INS_MOVF, &Capstone2LlvmIrTranslatorMips_impl::translateMovf},
		{MIPS_INS_MOVN, &Capstone2LlvmIrTranslatorMips_impl::translateMovn},
		{MIPS_INS_MOVT, &Capstone2LlvmIrTranslatorMips_impl::translateMovt},
		{MIPS_INS_MOVZ, &Capstone2LlvmIrTranslatorMips_impl::translateMovz},
		{MIPS_INS_MSUB, &Capstone2LlvmIrTranslatorMips_impl::translateMsub},
		{MIPS_INS_MSUBF, nullptr},
		{MIPS_INS_MSUBR_Q, nullptr},
		{MIPS_INS_MSUBU, &Capstone2LlvmIrTranslatorMips_impl::translateMsub},
		{MIPS_INS_MSUBV, nullptr},
		{MIPS_INS_MSUB_Q, nullptr},
		{MIPS_INS_MTC0, nullptr},
		{MIPS_INS_MTC1, &Capstone2LlvmIrTranslatorMips_impl::translateMtc1},
		{MIPS_INS_MTC2, nullptr},
		{MIPS_INS_MTHC1, nullptr},
		{MIPS_INS_MTHI, &Capstone2LlvmIrTranslatorMips_impl::translateMthi},
		{MIPS_INS_MTHLIP, nullptr},
		{MIPS_INS_MTLO, &Capstone2LlvmIrTranslatorMips_impl::translateMtlo},
		{MIPS_INS_MTM0, nullptr},
		{MIPS_INS_MTM1, nullptr},
		{MIPS_INS_MTM2, nullptr},
		{MIPS_INS_MTP0, nullptr},
		{MIPS_INS_MTP1, nullptr},
		{MIPS_INS_MTP2, nullptr},
		{MIPS_INS_MUH, nullptr},
		{MIPS_INS_MUHU, nullptr},
		{MIPS_INS_MULEQ_S, nullptr},
		{MIPS_INS_MULEU_S, nullptr},
		{MIPS_INS_MULQ_RS, nullptr},
		{MIPS_INS_MULQ_S, nullptr},
		{MIPS_INS_MULR_Q, nullptr},
		{MIPS_INS_MULSAQ_S, nullptr},
		{MIPS_INS_MULSA, nullptr},
		{MIPS_INS_MULT, &Capstone2LlvmIrTranslatorMips_impl::translateMult},
		{MIPS_INS_MULTU, &Capstone2LlvmIrTranslatorMips_impl::translateMult},
		{MIPS_INS_MULU, nullptr},
		{MIPS_INS_MULV, nullptr},
		{MIPS_INS_MUL_Q, nullptr},
		{MIPS_INS_MUL_S, nullptr},
		{MIPS_INS_NLOC, nullptr},
		{MIPS_INS_NLZC, nullptr},
		{MIPS_INS_NMADD, &Capstone2LlvmIrTranslatorMips_impl::translateNmadd},
		{MIPS_INS_NMSUB, &Capstone2LlvmIrTranslatorMips_impl::translateNmsub},
		{MIPS_INS_NOR, &Capstone2LlvmIrTranslatorMips_impl::translateNor},
		{MIPS_INS_NORI, &Capstone2LlvmIrTranslatorMips_impl::translateNor},
		{MIPS_INS_NOT16, nullptr},
		{MIPS_INS_NOT, &Capstone2LlvmIrTranslatorMips_impl::translateNot},
		{MIPS_INS_OR, &Capstone2LlvmIrTranslatorMips_impl::translateOr},
		{MIPS_INS_OR16, nullptr},
		{MIPS_INS_ORI, &Capstone2LlvmIrTranslatorMips_impl::translateOr},
		{MIPS_INS_PACKRL, nullptr},
		{MIPS_INS_PAUSE, nullptr},
		{MIPS_INS_PCKEV, nullptr},
		{MIPS_INS_PCKOD, nullptr},
		{MIPS_INS_PCNT, nullptr},
		{MIPS_INS_PICK, nullptr},
		{MIPS_INS_POP, nullptr},
		{MIPS_INS_PRECEQU, nullptr},
		{MIPS_INS_PRECEQ, nullptr},
		{MIPS_INS_PRECEU, nullptr},
		{MIPS_INS_PRECRQU_S, nullptr},
		{MIPS_INS_PRECRQ, nullptr},
		{MIPS_INS_PRECRQ_RS, nullptr},
		{MIPS_INS_PRECR, nullptr},
		{MIPS_INS_PRECR_SRA, nullptr},
		{MIPS_INS_PRECR_SRA_R, nullptr},
		{MIPS_INS_PREF, nullptr},
		{MIPS_INS_PREPEND, nullptr},
		{MIPS_INS_RADDU, nullptr},
		{MIPS_INS_RDDSP, nullptr},
		{MIPS_INS_RDHWR, nullptr},
		{MIPS_INS_REPLV, nullptr},
		{MIPS_INS_REPL, nullptr},
		{MIPS_INS_RINT, nullptr},
		{MIPS_INS_ROTR, &Capstone2LlvmIrTranslatorMips_impl::translateRotr},
		{MIPS_INS_ROTRV, &Capstone2LlvmIrTranslatorMips_impl::translateRotr},
		{MIPS_INS_ROUND, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_SAT_S, nullptr},
		{MIPS_INS_SAT_U, nullptr},
		{MIPS_INS_SB, &Capstone2LlvmIrTranslatorMips_impl::translateStoreMemory},
		{MIPS_INS_SB16, nullptr},
		{MIPS_INS_SC, nullptr},
		{MIPS_INS_SCD, nullptr},
		{MIPS_INS_SD, &Capstone2LlvmIrTranslatorMips_impl::translateStoreMemory},
		{MIPS_INS_SDBBP, nullptr},
		{MIPS_INS_SDBBP16, nullptr},
		{MIPS_INS_SDC1, &Capstone2LlvmIrTranslatorMips_impl::translateStoreMemory},
		{MIPS_INS_SDC2, nullptr},
		{MIPS_INS_SDC3, &Capstone2LlvmIrTranslatorMips_impl::translateStoreMemory},
		{MIPS_INS_SDL, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmFncOp0Op1},
		{MIPS_INS_SDR, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmFncOp0Op1},
		{MIPS_INS_SDXC1, nullptr},
		{MIPS_INS_SEB, &Capstone2LlvmIrTranslatorMips_impl::translateSeb},
		{MIPS_INS_SEH, &Capstone2LlvmIrTranslatorMips_impl::translateSeh},
		{MIPS_INS_SELEQZ, nullptr},
		{MIPS_INS_SELNEZ, nullptr},
		{MIPS_INS_SEL, nullptr},
		{MIPS_INS_SEQ, &Capstone2LlvmIrTranslatorMips_impl::translateSeq},
		{MIPS_INS_SEQI, &Capstone2LlvmIrTranslatorMips_impl::translateSeq},
		{MIPS_INS_SH, &Capstone2LlvmIrTranslatorMips_impl::translateStoreMemory},
		{MIPS_INS_SH16, nullptr},
		{MIPS_INS_SHF, nullptr},
		{MIPS_INS_SHILO, nullptr},
		{MIPS_INS_SHILOV, nullptr},
		{MIPS_INS_SHLLV, nullptr},
		{MIPS_INS_SHLLV_S, nullptr},
		{MIPS_INS_SHLL, nullptr},
		{MIPS_INS_SHLL_S, nullptr},
		{MIPS_INS_SHRAV, nullptr},
		{MIPS_INS_SHRAV_R, nullptr},
		{MIPS_INS_SHRA, nullptr},
		{MIPS_INS_SHRA_R, nullptr},
		{MIPS_INS_SHRLV, nullptr},
		{MIPS_INS_SHRL, nullptr},
		{MIPS_INS_SLDI, nullptr},
		{MIPS_INS_SLD, nullptr},
		{MIPS_INS_SLL, &Capstone2LlvmIrTranslatorMips_impl::translateSll},
		{MIPS_INS_SLL16, nullptr},
		{MIPS_INS_SLLI, &Capstone2LlvmIrTranslatorMips_impl::translateSll},
		{MIPS_INS_SLLV, &Capstone2LlvmIrTranslatorMips_impl::translateSll},
		{MIPS_INS_SLT, &Capstone2LlvmIrTranslatorMips_impl::translateSlt},
		{MIPS_INS_SLTI, &Capstone2LlvmIrTranslatorMips_impl::translateSlt},
		{MIPS_INS_SLTIU, &Capstone2LlvmIrTranslatorMips_impl::translateSltu},
		{MIPS_INS_SLTU, &Capstone2LlvmIrTranslatorMips_impl::translateSltu},
		{MIPS_INS_SNE, &Capstone2LlvmIrTranslatorMips_impl::translateSne},
		{MIPS_INS_SNEI, &Capstone2LlvmIrTranslatorMips_impl::translateSne},
		{MIPS_INS_SPLATI, nullptr},
		{MIPS_INS_SPLAT, nullptr},
		{MIPS_INS_SRA, &Capstone2LlvmIrTranslatorMips_impl::translateSra},
		{MIPS_INS_SRAI, &Capstone2LlvmIrTranslatorMips_impl::translateSra},
		{MIPS_INS_SRARI, nullptr},
		{MIPS_INS_SRAR, nullptr},
		{MIPS_INS_SRAV, &Capstone2LlvmIrTranslatorMips_impl::translateSra},
		{MIPS_INS_SRL, &Capstone2LlvmIrTranslatorMips_impl::translateSrl},
		{MIPS_INS_SRL16, nullptr},
		{MIPS_INS_SRLI, &Capstone2LlvmIrTranslatorMips_impl::translateSrl},
		{MIPS_INS_SRLRI, nullptr},
		{MIPS_INS_SRLR, nullptr},
		{MIPS_INS_SRLV, &Capstone2LlvmIrTranslatorMips_impl::translateSrl},
		{MIPS_INS_SSNOP, nullptr},
		{MIPS_INS_ST, nullptr},
		{MIPS_INS_SUBQH, nullptr},
		{MIPS_INS_SUBQH_R, nullptr},
		{MIPS_INS_SUBQ, nullptr},
		{MIPS_INS_SUBQ_S, nullptr},
		{MIPS_INS_SUBSUS_U, nullptr},
		{MIPS_INS_SUBSUU_S, nullptr},
		{MIPS_INS_SUBS_S, nullptr},
		{MIPS_INS_SUBS_U, nullptr},
		{MIPS_INS_SUBU16, nullptr},
		{MIPS_INS_SUBUH, nullptr},
		{MIPS_INS_SUBUH_R, nullptr},
		{MIPS_INS_SUBU, &Capstone2LlvmIrTranslatorMips_impl::translateSub},
		{MIPS_INS_SUBU_S, nullptr},
		{MIPS_INS_SUBVI, nullptr},
		{MIPS_INS_SUBV, nullptr},
		{MIPS_INS_SUXC1, nullptr},
		{MIPS_INS_SW, &Capstone2LlvmIrTranslatorMips_impl::translateStoreMemory},
		{MIPS_INS_SW16, nullptr},
		{MIPS_INS_SWC1, &Capstone2LlvmIrTranslatorMips_impl::translateStoreMemory},
		{MIPS_INS_SWC2, nullptr},
		{MIPS_INS_SWC3, nullptr},
		{MIPS_INS_SWL, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmFncOp0Op1},
		{MIPS_INS_SWM16, nullptr},
		{MIPS_INS_SWM32, nullptr},
		{MIPS_INS_SWP, nullptr},
		{MIPS_INS_SWR, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmFncOp0Op1},
		{MIPS_INS_SWXC1, nullptr},
		{MIPS_INS_SYNC, nullptr},
		{MIPS_INS_SYNCI, nullptr},
		{MIPS_INS_SYSCALL, &Capstone2LlvmIrTranslatorMips_impl::translateSyscall},
		// Not really a NOP, but often in places (e.g. main) where generating
		// pseudo asm call would break regression tests.
		{MIPS_INS_TEQ, &Capstone2LlvmIrTranslatorMips_impl::translateNop},
		{MIPS_INS_TEQI, nullptr},
		{MIPS_INS_TGE, nullptr},
		{MIPS_INS_TGEI, nullptr},
		{MIPS_INS_TGEIU, nullptr},
		{MIPS_INS_TGEU, nullptr},
		{MIPS_INS_TLBP, nullptr},
		{MIPS_INS_TLBR, nullptr},
		{MIPS_INS_TLBWI, nullptr},
		{MIPS_INS_TLBWR, nullptr},
		{MIPS_INS_TLT, nullptr},
		{MIPS_INS_TLTI, nullptr},
		{MIPS_INS_TLTIU, nullptr},
		{MIPS_INS_TLTU, nullptr},
		{MIPS_INS_TNE, nullptr},
		{MIPS_INS_TNEI, nullptr},
		{MIPS_INS_TRUNC, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_V3MULU, nullptr},
		{MIPS_INS_VMM0, nullptr},
		{MIPS_INS_VMULU, nullptr},
		{MIPS_INS_VSHF, nullptr},
		{MIPS_INS_WAIT, nullptr},
		{MIPS_INS_WRDSP, nullptr},
		{MIPS_INS_WSBH, &Capstone2LlvmIrTranslatorMips_impl::translatePseudoAsmOp0FncOp1},
		{MIPS_INS_XOR, &Capstone2LlvmIrTranslatorMips_impl::translateXor},
		{MIPS_INS_XOR16, nullptr},
		{MIPS_INS_XORI, &Capstone2LlvmIrTranslatorMips_impl::translateXor},

		// some alias instructions
		{MIPS_INS_NOP, &Capstone2LlvmIrTranslatorMips_impl::translateNop},
		{MIPS_INS_NEGU, &Capstone2LlvmIrTranslatorMips_impl::translateNegu},

		// special instructions
		{MIPS_INS_JALR_HB, nullptr}, // jump and link with Hazard Barrier
		{MIPS_INS_JR_HB, nullptr}, // jump register with Hazard Barrier

		{MIPS_INS_ENDING, nullptr},
};

} // namespace capstone2llvmir

