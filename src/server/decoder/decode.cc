/**
 * @brief LLVM-mc反汇编
 * @file src/server/decider/decode.c
 * @author lancerstadium
 * @date 2023-11-8
*/


#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#if LLVM_VERSION_MAJOR >= 14
#include <llvm/MC/TargetRegistry.h>
#if LLVM_VERSION_MAJOR >= 15
#include <llvm/MC/MCSubtargetInfo.h>
#endif
#else
#include <llvm/Support/TargetRegistry.h>
#endif
#include <llvm/Support/TargetSelect.h>

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#if LLVM_VERSION_MAJOR < 11
#error Please use LLVM with major version >= 11
#endif

using namespace llvm;

static llvm::MCDisassembler *gDisassembler = nullptr;   // 反汇编器
static llvm::MCSubtargetInfo *gSTI = nullptr;           // MC子目标信息
static llvm::MCInstPrinter *gIP = nullptr;              // MC指令信息打印器


// ============================================================================ //
// server API 实现 --> 定义 include/common.h
// ============================================================================ //

/// @brief 初始化反汇编引擎
/// @param triple 来宾体系结构字符串
extern "C" void init_disasm(const char *triple) {
    llvm::InitializeAllTargetInfos();
    llvm::InitializeAllTargetMCs();
    llvm::InitializeAllAsmParsers();
    llvm::InitializeAllDisassemblers();

    std::string errstr;
    std::string gTriple(triple);

    llvm::MCInstrInfo *gMII = nullptr;
    llvm::MCRegisterInfo *gMRI = nullptr;
    auto target = llvm::TargetRegistry::lookupTarget(gTriple, errstr);
    if (!target) {
        llvm::errs() << "Can't find target for " << gTriple << ": " << errstr << "\n";
        assert(0);
    }

    MCTargetOptions MCOptions;
    gSTI = target->createMCSubtargetInfo(gTriple, "", "");
    std::string isa = target->getName();
    if (isa == "riscv32" || isa == "riscv64") {
        gSTI->ApplyFeatureFlag("+m");
        gSTI->ApplyFeatureFlag("+a");
        gSTI->ApplyFeatureFlag("+c");
        gSTI->ApplyFeatureFlag("+f");
        gSTI->ApplyFeatureFlag("+d");
    }
    gMII = target->createMCInstrInfo();
    gMRI = target->createMCRegInfo(gTriple);
    auto AsmInfo = target->createMCAsmInfo(*gMRI, gTriple, MCOptions);
#if LLVM_VERSION_MAJOR >= 13
    auto llvmTripleTwine = Twine(triple);
    auto llvmtriple = llvm::Triple(llvmTripleTwine);
    auto Ctx = new llvm::MCContext(llvmtriple,AsmInfo, gMRI, nullptr);
#else
    auto Ctx = new llvm::MCContext(AsmInfo, gMRI, nullptr);
#endif
    gDisassembler = target->createMCDisassembler(*gSTI, *Ctx);
    gIP = target->createMCInstPrinter(llvm::Triple(gTriple),
        AsmInfo->getAssemblerDialect(), *AsmInfo, *gMII, *gMRI);
    gIP->setPrintImmHex(true);
    gIP->setPrintBranchImmAsAddress(true);
    if (isa == "riscv32" || isa == "riscv64")
        gIP->applyTargetSpecificCLOption("no-aliases");
}

/// @brief 反汇编
/// @param str 存储汇编指令的字符串
/// @param size 字符串长度
/// @param pc 指令计数器
/// @param code 开始地址
/// @param nbyte 指令长度
extern "C" void disassemble(char *str, int size, uint64_t pc, uint8_t *code, int nbyte) {
    MCInst inst;
    llvm::ArrayRef<uint8_t> arr(code, nbyte);
    uint64_t dummy_size = 0;
    gDisassembler->getInstruction(inst, dummy_size, arr, pc, llvm::nulls());

    std::string s;
    raw_string_ostream os(s);
    gIP->printInst(&inst, pc, "", *gSTI, os);

    int skip = s.find_first_not_of('\t');
    const char *p = s.c_str() + skip;
    assert((int)s.length() - skip < size);
    strcpy(str, p);
}

/// @brief 获取指令长度
/// @param pc 指令计数器
/// @param code 开始地址
/// @param nbyte 指令长度
/// @return 指令长度
extern "C" int get_inst_len(uint64_t pc, uint8_t *code, int nbyte) {
    MCInst inst;
    llvm::ArrayRef<uint8_t> arr(code, nbyte);
    uint64_t dummy_size = 0;
    gDisassembler->getInstruction(inst, dummy_size, arr, pc, llvm::nulls());

    return (int)dummy_size;
}
