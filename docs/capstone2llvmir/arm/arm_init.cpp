/**
 * @file include/capstone2llvmir/arm/arm_init.cpp
 * @brief ARM的`Capstone2LlvmIrTranslator`实现初始化。
 */

#include "capstone2llvmir/arm/arm_impl.h"


namespace capstone2llvmir {

//
//==============================================================================
// Pure virtual methods from Capstone2LlvmIrTranslator_impl
//==============================================================================
//

void Capstone2LlvmIrTranslatorArm_impl::initializeArchSpecific()
{
	// Nothing.
}

void Capstone2LlvmIrTranslatorArm_impl::initializeRegNameMap()
{
	std::map<uint32_t, std::string> r2n =
	{
			{ARM_REG_CPSR_N, "cpsr_n"},
			{ARM_REG_CPSR_Z, "cpsr_z"},
			{ARM_REG_CPSR_C, "cpsr_c"},
			{ARM_REG_CPSR_V, "cpsr_v"},
			// System registers - cs_reg_name() does not work on these.
			// SPSR* registers.
			// We cannot use these defines, they have the same numbers as
			// regular ARM registers.
//			{ARM_SYSREG_SPSR_C, "sysreg_spsr_c"},
//			{ARM_SYSREG_SPSR_X, "sysreg_spsr_x"},
//			{ARM_SYSREG_SPSR_S, "sysreg_spsr_s"},
//			{ARM_SYSREG_SPSR_F, "sysreg_spsr_f"},
			{ARM_SYSREG_SPSR, "sysreg_spsr"},
			// CPSR* registers.
			// We cannot use these defines, they have the same numbers as
			// regular ARM registers.
//			{ARM_SYSREG_CPSR_C, "sysreg_cpsr_c"},
//			{ARM_SYSREG_CPSR_X, "sysreg_cpsr_x"},
//			{ARM_SYSREG_CPSR_S, "sysreg_cpsr_s"},
//			{ARM_SYSREG_CPSR_F, "sysreg_cpsr_f"},
			{ARM_SYSREG_CPSR, "sysreg_cpsr"},
			// Independent registers.
			{ARM_SYSREG_APSR, "sysreg_apsr"},
			{ARM_SYSREG_APSR_G, "sysreg_apsr_g"},
			{ARM_SYSREG_APSR_NZCVQ, "sysreg_apsr_nzcvq"},
			{ARM_SYSREG_APSR_NZCVQG, "sysreg_apsr_nzcvqg"},
			{ARM_SYSREG_IAPSR, "sysreg_iapsr"},
			{ARM_SYSREG_IAPSR_G, "sysreg_iapsr_g"},
			{ARM_SYSREG_IAPSR_NZCVQG, "sysreg_iapsr_nzcvqg"},
			{ARM_SYSREG_IAPSR_NZCVQ, "sysreg_iapsr_nzcvq"},
			{ARM_SYSREG_EAPSR, "sysreg_eapsr"},
			{ARM_SYSREG_EAPSR_G, "sysreg_eapsr_g"},
			{ARM_SYSREG_EAPSR_NZCVQG, "sysreg_eapsr_nzcvqg"},
			{ARM_SYSREG_EAPSR_NZCVQ, "sysreg_eapsr_nzcvq"},
			{ARM_SYSREG_XPSR, "sysreg_xpsr"},
			{ARM_SYSREG_XPSR_G, "sysreg_xpsr_g"},
			{ARM_SYSREG_XPSR_NZCVQG, "sysreg_xpsr_nzcvqg"},
			{ARM_SYSREG_XPSR_NZCVQ, "sysreg_xpsr_nzcvq"},
			{ARM_SYSREG_IPSR, "sysreg_ipsr"},
			{ARM_SYSREG_EPSR, "sysreg_epsr"},
			{ARM_SYSREG_IEPSR, "sysreg_iepsr"},
			{ARM_SYSREG_MSP, "sysreg_msp"},
			{ARM_SYSREG_PSP, "sysreg_psp"},
			{ARM_SYSREG_PRIMASK, "sysreg_primask"},
			{ARM_SYSREG_BASEPRI, "sysreg_basepri"},
			{ARM_SYSREG_BASEPRI_MAX, "sysreg_basepri_max"},
			{ARM_SYSREG_FAULTMASK, "sysreg_faultmask"},
			{ARM_SYSREG_CONTROL, "sysreg_control"},
			{ARM_SYSREG_R8_USR, "sysreg_r8_usr"},
			{ARM_SYSREG_R9_USR, "sysreg_r9_usr"},
			{ARM_SYSREG_R10_USR, "sysreg_r10_usr"},
			{ARM_SYSREG_R11_USR, "sysreg_r11_usr"},
			{ARM_SYSREG_R12_USR, "sysreg_r12_usr"},
			{ARM_SYSREG_SP_USR, "sysreg_sp_usr"},
			{ARM_SYSREG_LR_USR, "sysreg_lr_usr"},
			{ARM_SYSREG_R8_FIQ, "sysreg_r8_fiq"},
			{ARM_SYSREG_R9_FIQ, "sysreg_r9_fiq"},
			{ARM_SYSREG_R10_FIQ, "sysreg_r10_fiq"},
			{ARM_SYSREG_R11_FIQ, "sysreg_r11_fiq"},
			{ARM_SYSREG_R12_FIQ, "sysreg_r12_fiq"},
			{ARM_SYSREG_SP_FIQ, "sysreg_sp_fiq"},
			{ARM_SYSREG_LR_FIQ, "sysreg_lr_fiq"},
			{ARM_SYSREG_LR_IRQ, "sysreg_lr_irq"},
			{ARM_SYSREG_SP_IRQ, "sysreg_sp_irq"},
			{ARM_SYSREG_LR_SVC, "sysreg_lr_svc"},
			{ARM_SYSREG_SP_SVC, "sysreg_sp_svc"},
			{ARM_SYSREG_LR_ABT, "sysreg_lr_abi"},
			{ARM_SYSREG_SP_ABT, "sysreg_sp_abi"},
			{ARM_SYSREG_LR_UND, "sysreg_lr_und"},
			{ARM_SYSREG_SP_UND, "sysreg_sp_und"},
			{ARM_SYSREG_LR_MON, "sysreg_lr_mon"},
			{ARM_SYSREG_SP_MON, "sysreg_sp_mon"},
			{ARM_SYSREG_ELR_HYP, "sysreg_elr_hyp"},
			{ARM_SYSREG_SP_HYP, "sysreg_sp_hyp"},
			{ARM_SYSREG_SPSR_FIQ, "sysreg_spsr_fiq"},
			{ARM_SYSREG_SPSR_IRQ, "sysreg_spsr_irq"},
			{ARM_SYSREG_SPSR_SVC, "sysreg_spsr_svc"},
			{ARM_SYSREG_SPSR_ABT, "sysreg_spsr_abi"},
			{ARM_SYSREG_SPSR_UND, "sysreg_spsr_und"},
			{ARM_SYSREG_SPSR_MON, "sysreg_spsr_mon"},
			{ARM_SYSREG_SPSR_HYP, "sysreg_spsr_hyp"},
	};

	_reg2name = std::move(r2n);
}

void Capstone2LlvmIrTranslatorArm_impl::initializeRegTypeMap()
{
	auto* i1 = llvm::IntegerType::getInt1Ty(_module->getContext());
	auto* i4 = llvm::IntegerType::getIntNTy(_module->getContext(), 4);
	auto* f32 = llvm::Type::getFloatTy(_module->getContext());
	auto* f64 = llvm::Type::getDoubleTy(_module->getContext());
	auto* f128 = llvm::Type::getFP128Ty(_module->getContext());
	auto* defTy = getDefaultType();

	std::map<uint32_t, llvm::Type*> r2t =
	{
			// General purpose registers.
			//
			{ARM_REG_R0, defTy},
			{ARM_REG_R1, defTy},
			{ARM_REG_R2, defTy},
			{ARM_REG_R3, defTy},
			{ARM_REG_R4, defTy},
			{ARM_REG_R5, defTy},
			{ARM_REG_R6, defTy},
			{ARM_REG_R7, defTy},
			{ARM_REG_R8, defTy},
			{ARM_REG_R9, defTy},
			{ARM_REG_R10, defTy},
			{ARM_REG_R11, defTy},
			{ARM_REG_R12, defTy},

			// Special registers.
			//
			{ARM_REG_SP, defTy},
			{ARM_REG_LR, defTy},
			{ARM_REG_PC, defTy},

			// CPSR flags.
			//
			{ARM_REG_CPSR_N, i1},
			{ARM_REG_CPSR_Z, i1},
			{ARM_REG_CPSR_C, i1},
			{ARM_REG_CPSR_V, i1},

			// All other registers - these were added just so we can generate
			// pseudo assembly calls with any register operands - they are not
			// properly handled.
			//
			{ARM_REG_APSR, defTy},
			{ARM_REG_APSR_NZCV, defTy},
			{ARM_REG_CPSR, defTy},
			{ARM_REG_FPEXC, defTy},
			{ARM_REG_FPINST, defTy},
			{ARM_REG_FPSCR, defTy},
			{ARM_REG_FPSCR_NZCV, defTy},
			{ARM_REG_FPSID, defTy},
			{ARM_REG_ITSTATE, defTy},
			{ARM_REG_SPSR, defTy},
			{ARM_REG_FPINST2, defTy},
			{ARM_REG_MVFR0, defTy},
			{ARM_REG_MVFR1, defTy},
			{ARM_REG_MVFR2, defTy},
			// NEON registers - shared reg. bank between Dx, Qx, Sx registers.
			// http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dht0002a/ch01s03s02.html
			// Dx = 32 x 64-bit FP
			{ARM_REG_D0, f64},
			{ARM_REG_D1, f64},
			{ARM_REG_D2, f64},
			{ARM_REG_D3, f64},
			{ARM_REG_D4, f64},
			{ARM_REG_D5, f64},
			{ARM_REG_D6, f64},
			{ARM_REG_D7, f64},
			{ARM_REG_D8, f64},
			{ARM_REG_D9, f64},
			{ARM_REG_D10, f64},
			{ARM_REG_D11, f64},
			{ARM_REG_D12, f64},
			{ARM_REG_D13, f64},
			{ARM_REG_D14, f64},
			{ARM_REG_D15, f64},
			{ARM_REG_D16, f64},
			{ARM_REG_D17, f64},
			{ARM_REG_D18, f64},
			{ARM_REG_D19, f64},
			{ARM_REG_D20, f64},
			{ARM_REG_D21, f64},
			{ARM_REG_D22, f64},
			{ARM_REG_D23, f64},
			{ARM_REG_D24, f64},
			{ARM_REG_D25, f64},
			{ARM_REG_D26, f64},
			{ARM_REG_D27, f64},
			{ARM_REG_D28, f64},
			{ARM_REG_D29, f64},
			{ARM_REG_D30, f64},
			{ARM_REG_D31, f64},
			// Qx = 16 x 128-bit FP
			{ARM_REG_Q0, f128},
			{ARM_REG_Q1, f128},
			{ARM_REG_Q2, f128},
			{ARM_REG_Q3, f128},
			{ARM_REG_Q4, f128},
			{ARM_REG_Q5, f128},
			{ARM_REG_Q6, f128},
			{ARM_REG_Q7, f128},
			{ARM_REG_Q8, f128},
			{ARM_REG_Q9, f128},
			{ARM_REG_Q10, f128},
			{ARM_REG_Q11, f128},
			{ARM_REG_Q12, f128},
			{ARM_REG_Q13, f128},
			{ARM_REG_Q14, f128},
			{ARM_REG_Q15, f128},
			// Sx = 32 x 32-bit FP
			{ARM_REG_S0, f32},
			{ARM_REG_S1, f32},
			{ARM_REG_S2, f32},
			{ARM_REG_S3, f32},
			{ARM_REG_S4, f32},
			{ARM_REG_S5, f32},
			{ARM_REG_S6, f32},
			{ARM_REG_S7, f32},
			{ARM_REG_S8, f32},
			{ARM_REG_S9, f32},
			{ARM_REG_S10, f32},
			{ARM_REG_S11, f32},
			{ARM_REG_S12, f32},
			{ARM_REG_S13, f32},
			{ARM_REG_S14, f32},
			{ARM_REG_S15, f32},
			{ARM_REG_S16, f32},
			{ARM_REG_S17, f32},
			{ARM_REG_S18, f32},
			{ARM_REG_S19, f32},
			{ARM_REG_S20, f32},
			{ARM_REG_S21, f32},
			{ARM_REG_S22, f32},
			{ARM_REG_S23, f32},
			{ARM_REG_S24, f32},
			{ARM_REG_S25, f32},
			{ARM_REG_S26, f32},
			{ARM_REG_S27, f32},
			{ARM_REG_S28, f32},
			{ARM_REG_S29, f32},
			{ARM_REG_S30, f32},
			{ARM_REG_S31, f32},
			// System registers.
			// SPSR* registers.
			// We cannot use these defines, they have the same numbers as
			// regular ARM registers.
//			{ARM_SYSREG_SPSR_C, i1},
//			{ARM_SYSREG_SPSR_X, i1},
//			{ARM_SYSREG_SPSR_S, i1},
//			{ARM_SYSREG_SPSR_F, i1},
			{ARM_SYSREG_SPSR, i4},
			// CPSR* registers.
			// We cannot use these defines, they have the same numbers as
			// regular ARM registers.
//			{ARM_SYSREG_CPSR_C, i1},
//			{ARM_SYSREG_CPSR_X, i1},
//			{ARM_SYSREG_CPSR_S, i1},
//			{ARM_SYSREG_CPSR_F, i1},
			{ARM_SYSREG_CPSR, i4},
			// Independent registers.
			{ARM_SYSREG_APSR, defTy},
			{ARM_SYSREG_APSR_G, defTy},
			{ARM_SYSREG_APSR_NZCVQ, defTy},
			{ARM_SYSREG_APSR_NZCVQG, defTy},
			{ARM_SYSREG_IAPSR, defTy},
			{ARM_SYSREG_IAPSR_G, defTy},
			{ARM_SYSREG_IAPSR_NZCVQG, defTy},
			{ARM_SYSREG_IAPSR_NZCVQ, defTy},
			{ARM_SYSREG_EAPSR, defTy},
			{ARM_SYSREG_EAPSR_G, defTy},
			{ARM_SYSREG_EAPSR_NZCVQG, defTy},
			{ARM_SYSREG_EAPSR_NZCVQ, defTy},
			{ARM_SYSREG_XPSR, defTy},
			{ARM_SYSREG_XPSR_G, defTy},
			{ARM_SYSREG_XPSR_NZCVQG, defTy},
			{ARM_SYSREG_XPSR_NZCVQ, defTy},
			{ARM_SYSREG_IPSR, defTy},
			{ARM_SYSREG_EPSR, defTy},
			{ARM_SYSREG_IEPSR, defTy},
			{ARM_SYSREG_MSP, defTy},
			{ARM_SYSREG_PSP, defTy},
			{ARM_SYSREG_PRIMASK, defTy},
			{ARM_SYSREG_BASEPRI, defTy},
			{ARM_SYSREG_BASEPRI_MAX, defTy},
			{ARM_SYSREG_FAULTMASK, defTy},
			{ARM_SYSREG_CONTROL, defTy},
			{ARM_SYSREG_R8_USR, defTy},
			{ARM_SYSREG_R9_USR, defTy},
			{ARM_SYSREG_R10_USR, defTy},
			{ARM_SYSREG_R11_USR, defTy},
			{ARM_SYSREG_R12_USR, defTy},
			{ARM_SYSREG_SP_USR, defTy},
			{ARM_SYSREG_LR_USR, defTy},
			{ARM_SYSREG_R8_FIQ, defTy},
			{ARM_SYSREG_R9_FIQ, defTy},
			{ARM_SYSREG_R10_FIQ, defTy},
			{ARM_SYSREG_R11_FIQ, defTy},
			{ARM_SYSREG_R12_FIQ, defTy},
			{ARM_SYSREG_SP_FIQ, defTy},
			{ARM_SYSREG_LR_FIQ, defTy},
			{ARM_SYSREG_LR_IRQ, defTy},
			{ARM_SYSREG_SP_IRQ, defTy},
			{ARM_SYSREG_LR_SVC, defTy},
			{ARM_SYSREG_SP_SVC, defTy},
			{ARM_SYSREG_LR_ABT, defTy},
			{ARM_SYSREG_SP_ABT, defTy},
			{ARM_SYSREG_LR_UND, defTy},
			{ARM_SYSREG_SP_UND, defTy},
			{ARM_SYSREG_LR_MON, defTy},
			{ARM_SYSREG_SP_MON, defTy},
			{ARM_SYSREG_ELR_HYP, defTy},
			{ARM_SYSREG_SP_HYP, defTy},
			{ARM_SYSREG_SPSR_FIQ, defTy},
			{ARM_SYSREG_SPSR_IRQ, defTy},
			{ARM_SYSREG_SPSR_SVC, defTy},
			{ARM_SYSREG_SPSR_ABT, defTy},
			{ARM_SYSREG_SPSR_UND, defTy},
			{ARM_SYSREG_SPSR_MON, defTy},
			{ARM_SYSREG_SPSR_HYP, defTy},
	};

	_reg2type = std::move(r2t);
}

void Capstone2LlvmIrTranslatorArm_impl::initializePseudoCallInstructionIDs()
{
	_callInsnIds =
	{

	};

	_returnInsnIds =
	{
			// Nothing - ARM returns via write to program counter register.
	};

	_branchInsnIds =
	{

	};

	_condBranchInsnIds =
	{

	};

	_controlFlowInsnIds =
	{
			ARM_INS_BL,
			ARM_INS_BLX,
			ARM_INS_B,
			ARM_INS_BX,
			ARM_INS_CBNZ,
			ARM_INS_CBZ,
	};
}

//
//==============================================================================
// Instruction translation map initialization.
//==============================================================================
//

std::map<
	std::size_t,
	void (Capstone2LlvmIrTranslatorArm_impl::*)(
			cs_insn* i,
			cs_arm*,
			llvm::IRBuilder<>&)>
Capstone2LlvmIrTranslatorArm_impl::_i2fm =
{
		{ARM_INS_INVALID, nullptr},

		{ARM_INS_ADC, &Capstone2LlvmIrTranslatorArm_impl::translateAdc},
		{ARM_INS_ADD, &Capstone2LlvmIrTranslatorArm_impl::translateAdd},
		{ARM_INS_ADR, nullptr},
		{ARM_INS_AESD, nullptr},
		{ARM_INS_AESE, nullptr},
		{ARM_INS_AESIMC, nullptr},
		{ARM_INS_AESMC, nullptr},
		{ARM_INS_AND, &Capstone2LlvmIrTranslatorArm_impl::translateAnd},
		{ARM_INS_BFC, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp0Op1Op2},
		{ARM_INS_BFI, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp0Op1Op2Op3},
		{ARM_INS_BIC, &Capstone2LlvmIrTranslatorArm_impl::translateAnd},
		{ARM_INS_BKPT, nullptr},
		{ARM_INS_BL, &Capstone2LlvmIrTranslatorArm_impl::translateBl},
		{ARM_INS_BLX, &Capstone2LlvmIrTranslatorArm_impl::translateBl},
		{ARM_INS_BX, &Capstone2LlvmIrTranslatorArm_impl::translateB},
		{ARM_INS_BXJ, nullptr},
		{ARM_INS_B, &Capstone2LlvmIrTranslatorArm_impl::translateB},
		{ARM_INS_CDP, nullptr},
		{ARM_INS_CDP2, nullptr},
		{ARM_INS_CLREX, nullptr},
		{ARM_INS_CLZ, &Capstone2LlvmIrTranslatorArm_impl::translateClz},
		{ARM_INS_CMN, &Capstone2LlvmIrTranslatorArm_impl::translateAdd},
		{ARM_INS_CMP, &Capstone2LlvmIrTranslatorArm_impl::translateSub},
		{ARM_INS_CPS, nullptr},
		{ARM_INS_CRC32B, nullptr},
		{ARM_INS_CRC32CB, nullptr},
		{ARM_INS_CRC32CH, nullptr},
		{ARM_INS_CRC32CW, nullptr},
		{ARM_INS_CRC32H, nullptr},
		{ARM_INS_CRC32W, nullptr},
		{ARM_INS_DBG, nullptr},
		{ARM_INS_DMB, nullptr},
		{ARM_INS_DSB, nullptr},
		{ARM_INS_EOR, &Capstone2LlvmIrTranslatorArm_impl::translateEor},
		{ARM_INS_ERET, nullptr},
		{ARM_INS_VMOV, nullptr},
		{ARM_INS_FLDMDBX, nullptr},
		{ARM_INS_FLDMIAX, nullptr},
		{ARM_INS_VMRS, nullptr},
		{ARM_INS_FSTMDBX, nullptr},
		{ARM_INS_FSTMIAX, nullptr},
		{ARM_INS_HINT, nullptr},
		{ARM_INS_HLT, nullptr},
		{ARM_INS_HVC, nullptr},
		{ARM_INS_ISB, nullptr},
		{ARM_INS_LDA, nullptr},
		{ARM_INS_LDAB, nullptr},
		{ARM_INS_LDAEX, nullptr},
		{ARM_INS_LDAEXB, nullptr},
		{ARM_INS_LDAEXD, nullptr},
		{ARM_INS_LDAEXH, nullptr},
		{ARM_INS_LDAH, nullptr},
		{ARM_INS_LDC2L, nullptr},
		{ARM_INS_LDC2, nullptr},
		{ARM_INS_LDCL, nullptr},
		{ARM_INS_LDC, nullptr},
		{ARM_INS_LDMDA, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_LDMDB, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_LDM, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_LDMIB, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_LDRBT, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRB, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRD, &Capstone2LlvmIrTranslatorArm_impl::translateLdrd},
		{ARM_INS_LDREX, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDREXB, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDREXD, &Capstone2LlvmIrTranslatorArm_impl::translateLdrd},
		{ARM_INS_LDREXH, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRH, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRHT, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRSB, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRSBT, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRSH, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRSHT, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDRT, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_LDR, &Capstone2LlvmIrTranslatorArm_impl::translateLdr},
		{ARM_INS_MCR, nullptr},
		{ARM_INS_MCR2, nullptr},
		{ARM_INS_MCRR, nullptr},
		{ARM_INS_MCRR2, nullptr},
		{ARM_INS_MLA, &Capstone2LlvmIrTranslatorArm_impl::translateMla},
		{ARM_INS_MLS, &Capstone2LlvmIrTranslatorArm_impl::translateMls},
		{ARM_INS_MOV, &Capstone2LlvmIrTranslatorArm_impl::translateMov},
		{ARM_INS_MOVS, &Capstone2LlvmIrTranslatorArm_impl::translateMov},
		{ARM_INS_MOVT, &Capstone2LlvmIrTranslatorArm_impl::translateMovt},
		{ARM_INS_MOVW, &Capstone2LlvmIrTranslatorArm_impl::translateMovw},
		{ARM_INS_MRC, nullptr},
		{ARM_INS_MRC2, nullptr},
		{ARM_INS_MRRC, nullptr},
		{ARM_INS_MRRC2, nullptr},
		{ARM_INS_MRS, nullptr},
		{ARM_INS_MSR, nullptr},
		{ARM_INS_MUL, &Capstone2LlvmIrTranslatorArm_impl::translateMul},
		{ARM_INS_MVN, &Capstone2LlvmIrTranslatorArm_impl::translateMov},
		{ARM_INS_ORR, &Capstone2LlvmIrTranslatorArm_impl::translateOrr},
		{ARM_INS_PKHBT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_PKHTB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_PLDW, nullptr},
		{ARM_INS_PLD, nullptr},
		{ARM_INS_PLI, nullptr},
		{ARM_INS_QADD, nullptr},
		{ARM_INS_QADD16, nullptr},
		{ARM_INS_QADD8, nullptr},
		{ARM_INS_QASX, nullptr},
		{ARM_INS_QDADD, nullptr},
		{ARM_INS_QDSUB, nullptr},
		{ARM_INS_QSAX, nullptr},
		{ARM_INS_QSUB, nullptr},
		{ARM_INS_QSUB16, nullptr},
		{ARM_INS_QSUB8, nullptr},
		{ARM_INS_RBIT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1},
		{ARM_INS_REV, &Capstone2LlvmIrTranslatorArm_impl::translateRev},
		{ARM_INS_REV16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1},
		{ARM_INS_REVSH, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1},
		{ARM_INS_RFEDA, nullptr},
		{ARM_INS_RFEDB, nullptr},
		{ARM_INS_RFEIA, nullptr},
		{ARM_INS_RFEIB, nullptr},
		{ARM_INS_RSB, &Capstone2LlvmIrTranslatorArm_impl::translateSub},
		{ARM_INS_RSC, &Capstone2LlvmIrTranslatorArm_impl::translateSbc},
		{ARM_INS_SADD16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SADD8, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SASX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SBC, &Capstone2LlvmIrTranslatorArm_impl::translateSbc},
		{ARM_INS_SBFX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SDIV, nullptr},
		{ARM_INS_SEL, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SETEND, nullptr},
		{ARM_INS_SHA1C, nullptr},
		{ARM_INS_SHA1H, nullptr},
		{ARM_INS_SHA1M, nullptr},
		{ARM_INS_SHA1P, nullptr},
		{ARM_INS_SHA1SU0, nullptr},
		{ARM_INS_SHA1SU1, nullptr},
		{ARM_INS_SHA256H, nullptr},
		{ARM_INS_SHA256H2, nullptr},
		{ARM_INS_SHA256SU0, nullptr},
		{ARM_INS_SHA256SU1, nullptr},
		{ARM_INS_SHADD16, nullptr},
		{ARM_INS_SHADD8, nullptr},
		{ARM_INS_SHASX, nullptr},
		{ARM_INS_SHSAX, nullptr},
		{ARM_INS_SHSUB16, nullptr},
		{ARM_INS_SHSUB8, nullptr},
		{ARM_INS_SMC, nullptr},
		{ARM_INS_SMLABB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLABT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLAD, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLADX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLAL, &Capstone2LlvmIrTranslatorArm_impl::translateUmlal},
		{ARM_INS_SMLALBB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_SMLALBT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_SMLALD, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_SMLALDX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_SMLALTB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_SMLALTT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_SMLATB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLATT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLAWB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLAWT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLSD, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLSDX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMLSLD, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_SMLSLDX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_SMMLA, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMMLAR, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMMLS, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMMLSR, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_SMMUL, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMMULR, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMUAD, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMUADX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMULBB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMULBT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMULL, &Capstone2LlvmIrTranslatorArm_impl::translateUmull},
		{ARM_INS_SMULTB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMULTT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMULWB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMULWT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SMUSD, nullptr},
		{ARM_INS_SMUSDX, nullptr},
		{ARM_INS_SRSDA, nullptr},
		{ARM_INS_SRSDB, nullptr},
		{ARM_INS_SRSIA, nullptr},
		{ARM_INS_SRSIB, nullptr},
		{ARM_INS_SSAT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SSAT16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SSAX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SSUB16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SSUB8, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_STC2L, nullptr},
		{ARM_INS_STC2, nullptr},
		{ARM_INS_STCL, nullptr},
		{ARM_INS_STC, nullptr},
		{ARM_INS_STL, nullptr},
		{ARM_INS_STLB, nullptr},
		{ARM_INS_STLEX, nullptr},
		{ARM_INS_STLEXB, nullptr},
		{ARM_INS_STLEXD, nullptr},
		{ARM_INS_STLEXH, nullptr},
		{ARM_INS_STLH, nullptr},
		{ARM_INS_STMDA, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_STMDB, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_STM, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_STMIB, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_STRBT, &Capstone2LlvmIrTranslatorArm_impl::translateStr},
		{ARM_INS_STRB, &Capstone2LlvmIrTranslatorArm_impl::translateStr},
		{ARM_INS_STRD, &Capstone2LlvmIrTranslatorArm_impl::translateStr},
		{ARM_INS_STREX, nullptr},
		{ARM_INS_STREXB, nullptr},
		{ARM_INS_STREXD, nullptr},
		{ARM_INS_STREXH, nullptr},
		{ARM_INS_STRH, &Capstone2LlvmIrTranslatorArm_impl::translateStr},
		{ARM_INS_STRHT, &Capstone2LlvmIrTranslatorArm_impl::translateStr},
		{ARM_INS_STRT, &Capstone2LlvmIrTranslatorArm_impl::translateStr},
		{ARM_INS_STR, &Capstone2LlvmIrTranslatorArm_impl::translateStr},
		{ARM_INS_SUB, &Capstone2LlvmIrTranslatorArm_impl::translateSub},
		{ARM_INS_SVC, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmFncOp0},
		{ARM_INS_SWP, nullptr},
		{ARM_INS_SWPB, nullptr},
		{ARM_INS_SXTAB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SXTAB16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SXTAH, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_SXTB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1},
		{ARM_INS_SXTB16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1},
		{ARM_INS_SXTH, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1},
		{ARM_INS_TEQ, &Capstone2LlvmIrTranslatorArm_impl::translateEor},
		{ARM_INS_TRAP, nullptr},
		{ARM_INS_TST, &Capstone2LlvmIrTranslatorArm_impl::translateAnd},
		{ARM_INS_UADD16, nullptr},
		{ARM_INS_UADD8, nullptr},
		{ARM_INS_UASX, nullptr},
		{ARM_INS_UBFX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_UDF, nullptr},
		{ARM_INS_UDIV, nullptr},
		{ARM_INS_UHADD16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UHADD8, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UHASX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UHSAX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UHSUB16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UHSUB8, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UMAAL, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3},
		{ARM_INS_UMLAL, &Capstone2LlvmIrTranslatorArm_impl::translateUmlal},
		{ARM_INS_UMULL, &Capstone2LlvmIrTranslatorArm_impl::translateUmull},
		{ARM_INS_UQADD16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UQADD8, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UQASX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UQSAX, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UQSUB16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UQSUB8, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_USAD8, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_USADA8, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2Op3},
		{ARM_INS_USAT, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_USAT16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_USAX, nullptr},
		{ARM_INS_USUB16, nullptr},
		{ARM_INS_USUB8, nullptr},
		{ARM_INS_UXTAB, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UXTAB16, &Capstone2LlvmIrTranslatorArm_impl::translatePseudoAsmOp0FncOp1Op2},
		{ARM_INS_UXTAH, &Capstone2LlvmIrTranslatorArm_impl::translateUxtah},
		{ARM_INS_UXTB, &Capstone2LlvmIrTranslatorArm_impl::translateUxtb},
		{ARM_INS_UXTB16, &Capstone2LlvmIrTranslatorArm_impl::translateUxtb16},
		{ARM_INS_UXTH, &Capstone2LlvmIrTranslatorArm_impl::translateUxth},
		{ARM_INS_VABAL, nullptr},
		{ARM_INS_VABA, nullptr},
		{ARM_INS_VABDL, nullptr},
		{ARM_INS_VABD, nullptr},
		{ARM_INS_VABS, nullptr},
		{ARM_INS_VACGE, nullptr},
		{ARM_INS_VACGT, nullptr},
		{ARM_INS_VADD, nullptr},
		{ARM_INS_VADDHN, nullptr},
		{ARM_INS_VADDL, nullptr},
		{ARM_INS_VADDW, nullptr},
		{ARM_INS_VAND, nullptr},
		{ARM_INS_VBIC, nullptr},
		{ARM_INS_VBIF, nullptr},
		{ARM_INS_VBIT, nullptr},
		{ARM_INS_VBSL, nullptr},
		{ARM_INS_VCEQ, nullptr},
		{ARM_INS_VCGE, nullptr},
		{ARM_INS_VCGT, nullptr},
		{ARM_INS_VCLE, nullptr},
		{ARM_INS_VCLS, nullptr},
		{ARM_INS_VCLT, nullptr},
		{ARM_INS_VCLZ, nullptr},
		{ARM_INS_VCMP, nullptr},
		{ARM_INS_VCMPE, nullptr},
		{ARM_INS_VCNT, nullptr},
		{ARM_INS_VCVTA, nullptr},
		{ARM_INS_VCVTB, nullptr},
		{ARM_INS_VCVT, nullptr},
		{ARM_INS_VCVTM, nullptr},
		{ARM_INS_VCVTN, nullptr},
		{ARM_INS_VCVTP, nullptr},
		{ARM_INS_VCVTT, nullptr},
		{ARM_INS_VDIV, nullptr},
		{ARM_INS_VDUP, nullptr},
		{ARM_INS_VEOR, nullptr},
		{ARM_INS_VEXT, nullptr},
		{ARM_INS_VFMA, nullptr},
		{ARM_INS_VFMS, nullptr},
		{ARM_INS_VFNMA, nullptr},
		{ARM_INS_VFNMS, nullptr},
		{ARM_INS_VHADD, nullptr},
		{ARM_INS_VHSUB, nullptr},
		{ARM_INS_VLD1, nullptr},
		{ARM_INS_VLD2, nullptr},
		{ARM_INS_VLD3, nullptr},
		{ARM_INS_VLD4, nullptr},
		{ARM_INS_VLDMDB, nullptr},
		{ARM_INS_VLDMIA, nullptr},
		{ARM_INS_VLDR, nullptr},
		{ARM_INS_VMAXNM, nullptr},
		{ARM_INS_VMAX, nullptr},
		{ARM_INS_VMINNM, nullptr},
		{ARM_INS_VMIN, nullptr},
		{ARM_INS_VMLA, nullptr},
		{ARM_INS_VMLAL, nullptr},
		{ARM_INS_VMLS, nullptr},
		{ARM_INS_VMLSL, nullptr},
		{ARM_INS_VMOVL, nullptr},
		{ARM_INS_VMOVN, nullptr},
		{ARM_INS_VMSR, nullptr},
		{ARM_INS_VMUL, nullptr},
		{ARM_INS_VMULL, nullptr},
		{ARM_INS_VMVN, nullptr},
		{ARM_INS_VNEG, nullptr},
		{ARM_INS_VNMLA, nullptr},
		{ARM_INS_VNMLS, nullptr},
		{ARM_INS_VNMUL, nullptr},
		{ARM_INS_VORN, nullptr},
		{ARM_INS_VORR, nullptr},
		{ARM_INS_VPADAL, nullptr},
		{ARM_INS_VPADDL, nullptr},
		{ARM_INS_VPADD, nullptr},
		{ARM_INS_VPMAX, nullptr},
		{ARM_INS_VPMIN, nullptr},
		{ARM_INS_VQABS, nullptr},
		{ARM_INS_VQADD, nullptr},
		{ARM_INS_VQDMLAL, nullptr},
		{ARM_INS_VQDMLSL, nullptr},
		{ARM_INS_VQDMULH, nullptr},
		{ARM_INS_VQDMULL, nullptr},
		{ARM_INS_VQMOVUN, nullptr},
		{ARM_INS_VQMOVN, nullptr},
		{ARM_INS_VQNEG, nullptr},
		{ARM_INS_VQRDMULH, nullptr},
		{ARM_INS_VQRSHL, nullptr},
		{ARM_INS_VQRSHRN, nullptr},
		{ARM_INS_VQRSHRUN, nullptr},
		{ARM_INS_VQSHL, nullptr},
		{ARM_INS_VQSHLU, nullptr},
		{ARM_INS_VQSHRN, nullptr},
		{ARM_INS_VQSHRUN, nullptr},
		{ARM_INS_VQSUB, nullptr},
		{ARM_INS_VRADDHN, nullptr},
		{ARM_INS_VRECPE, nullptr},
		{ARM_INS_VRECPS, nullptr},
		{ARM_INS_VREV16, nullptr},
		{ARM_INS_VREV32, nullptr},
		{ARM_INS_VREV64, nullptr},
		{ARM_INS_VRHADD, nullptr},
		{ARM_INS_VRINTA, nullptr},
		{ARM_INS_VRINTM, nullptr},
		{ARM_INS_VRINTN, nullptr},
		{ARM_INS_VRINTP, nullptr},
		{ARM_INS_VRINTR, nullptr},
		{ARM_INS_VRINTX, nullptr},
		{ARM_INS_VRINTZ, nullptr},
		{ARM_INS_VRSHL, nullptr},
		{ARM_INS_VRSHRN, nullptr},
		{ARM_INS_VRSHR, nullptr},
		{ARM_INS_VRSQRTE, nullptr},
		{ARM_INS_VRSQRTS, nullptr},
		{ARM_INS_VRSRA, nullptr},
		{ARM_INS_VRSUBHN, nullptr},
		{ARM_INS_VSELEQ, nullptr},
		{ARM_INS_VSELGE, nullptr},
		{ARM_INS_VSELGT, nullptr},
		{ARM_INS_VSELVS, nullptr},
		{ARM_INS_VSHLL, nullptr},
		{ARM_INS_VSHL, nullptr},
		{ARM_INS_VSHRN, nullptr},
		{ARM_INS_VSHR, nullptr},
		{ARM_INS_VSLI, nullptr},
		{ARM_INS_VSQRT, nullptr},
		{ARM_INS_VSRA, nullptr},
		{ARM_INS_VSRI, nullptr},
		{ARM_INS_VST1, nullptr},
		{ARM_INS_VST2, nullptr},
		{ARM_INS_VST3, nullptr},
		{ARM_INS_VST4, nullptr},
		{ARM_INS_VSTMDB, nullptr},
		{ARM_INS_VSTMIA, nullptr},
		{ARM_INS_VSTR, nullptr},
		{ARM_INS_VSUB, nullptr},
		{ARM_INS_VSUBHN, nullptr},
		{ARM_INS_VSUBL, nullptr},
		{ARM_INS_VSUBW, nullptr},
		{ARM_INS_VSWP, nullptr},
		{ARM_INS_VTBL, nullptr},
		{ARM_INS_VTBX, nullptr},
		{ARM_INS_VCVTR, nullptr},
		{ARM_INS_VTRN, nullptr},
		{ARM_INS_VTST, nullptr},
		{ARM_INS_VUZP, nullptr},
		{ARM_INS_VZIP, nullptr},
		{ARM_INS_ADDW, nullptr},
		{ARM_INS_ASR, &Capstone2LlvmIrTranslatorArm_impl::translateShifts},
		{ARM_INS_DCPS1, nullptr},
		{ARM_INS_DCPS2, nullptr},
		{ARM_INS_DCPS3, nullptr},
		{ARM_INS_IT, nullptr},
		{ARM_INS_LSL, &Capstone2LlvmIrTranslatorArm_impl::translateShifts},
		{ARM_INS_LSR, &Capstone2LlvmIrTranslatorArm_impl::translateShifts},
		{ARM_INS_ORN, nullptr},
		{ARM_INS_ROR, &Capstone2LlvmIrTranslatorArm_impl::translateShifts},
		{ARM_INS_RRX, &Capstone2LlvmIrTranslatorArm_impl::translateShifts},
		{ARM_INS_SUBW, nullptr},
		{ARM_INS_TBB, nullptr},
		{ARM_INS_TBH, nullptr},
		{ARM_INS_CBNZ, &Capstone2LlvmIrTranslatorArm_impl::translateCbnz},
		{ARM_INS_CBZ, &Capstone2LlvmIrTranslatorArm_impl::translateCbz},
		{ARM_INS_POP, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},
		{ARM_INS_PUSH, &Capstone2LlvmIrTranslatorArm_impl::translateLdmStm},

		// special instructions
		{ARM_INS_NOP, &Capstone2LlvmIrTranslatorArm_impl::translateNop},
		{ARM_INS_YIELD, nullptr},
		{ARM_INS_WFE, nullptr},
		{ARM_INS_WFI, nullptr},
		{ARM_INS_SEV, nullptr},
		{ARM_INS_SEVL, nullptr},
		{ARM_INS_VPUSH, nullptr},
		{ARM_INS_VPOP, nullptr},

		{ARM_INS_ENDING, nullptr},
};

} // namespace capstone2llvmir

