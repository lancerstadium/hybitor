/// \file translator.hpp
/// \brief 翻译器以及相关操作

// 本地库
#include "loader.hpp"
#include "writer.hpp"
#include "disassembler.hpp"
#include "core/CodeStruct/TranslatedStruct.hpp"

using BasicStruct::BasicBlock;
using TranslationStruct::TranslationBlock;
using TranslationStruct::TranslationResultOne;

class translator
{
private:
    disassembler das;
    TranslationBlock tb;
    TranslationResultOne tro;

public:
    translator(string input_file, string output_file) : das(input_file, output_file){};
    ~translator(){};

    /// @brief
    /// @param bytes
    /// @param size
    /// @param address
    /// @param handle
    /// @param irb
    /// @return
    TranslationResultOne add_tb_result_one(
        const uint8_t *&bytes,
        std::size_t &size,
        uint64_t address,
        llvm::IRBuilder<> &irb)
    {
        TranslationResultOne res;

        // We want to keep all Capstone instructions -> alloc a new one each time.
        cs_insn *insn = cs_malloc(this->das.handle);

        uint64_t u_address = address;
        res.branchCall = nullptr;
        res.inCondition = false;

        // TODO: hack, solve better.
        bool hasAsmRes = cs_disasm_iter(this->das.handle, &bytes, &size, &u_address, insn);

        if (hasAsmRes)
        {
            auto *a2l = generate_special_asm_2_llvmir(irb, insn);
            this->translate_instruction(insn, irb);

            res.llvmInsn = a2l;
            res.capstoneInsn = insn;
            res.size = insn->size;
            address = u_address;
        }
        else
        {
            cs_free(insn, 1);
        }

        return res;
    }

    void translate_instruction(cs_insn *i, llvm::IRBuilder<> &irb)
    {
    }

    llvm::StoreInst* generate_special_asm_2_llvmir(llvm::IRBuilder<> &irb, cs_insn *i)
    {
        // uint64_t a = i->address;
        // auto *gv = getAsm2LlvmMapGlobalVariable();
        // auto *ci = llvm::ConstantInt::get(gv->getValueType(), a, false);
        // auto *s = irb.CreateStore(ci, gv, true);
        // return s;
    }
};
