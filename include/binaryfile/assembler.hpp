/// \file assembler.hpp
/// \brief 文件反汇编器以及相关操作

#ifndef ASSEMBLER_HPP
#define ASSEMBLER_HPP

#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>
#include <llvm/ADT/STLExtras.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include "loader.hpp"

class assembler
{
private:
public:
    loader &ld;
    string output_file_path;
    assembler(loader &loader, string outputfile) : ld(loader), output_file_path(outputfile) {};
    ~assembler(){};

    int file_to_block()
    {
        llvm::LLVMContext context;
        llvm::InitializeAllTargetInfos();
        llvm::InitializeAllTargets();
        llvm::InitializeAllTargetMCs();
        llvm::InitializeAllAsmPrinters();
        llvm::InitializeAllAsmParsers();

        llvm::BasicBlock *basicBlock = loadBinaryToBlock(context);

        if (basicBlock)
        {
            // 在这里你可以继续添加其他 LLVM IR 操作
        }

        return 0;
    }

    // 解析二进制文件并将其装载成基本块
    llvm::BasicBlock *loadBinaryToBlock(llvm::LLVMContext &context)
    {
        // 创建一个新的 LLVM 模块和函数
        llvm::Module module("MyModule", context);
        llvm::IRBuilder<> builder(context);

        llvm::FunctionType *funcType = llvm::FunctionType::get(builder.getVoidTy(), false);
        llvm::Function *function = llvm::Function::Create(funcType, llvm::Function::ExternalLinkage, "myFunction", module);
        llvm::BasicBlock *basicBlock = llvm::BasicBlock::Create(context, "entry", function);

        // 使用 LIEF 解析二进制文件
        auto binary = LIEF::Parser::parse(this->ld.elf_file_name);
        if (!binary)
        {
            llvm::errs() << "Failed to parse binary file\n";
            return nullptr;
        }

        // 使用 Capstone 反汇编并将指令添加到基本块
        cs_insn *insn;
        size_t count;

        // 
        if(this->ld.open_capstone_engine(CS_ARCH_X86, CS_MODE_64) == -1)
        {
            return nullptr;
        }

        for (const auto &section : binary->sections())
        {
            if (section.content().empty())
            {
                continue;
            }

            count = cs_disasm(this->ld.handle, section.content().data(), section.content().size(), section.virtual_address(), 0, &insn);
            if (count > 0)
            {
                for (size_t i = 0; i < count; ++i)
                {
                    // 获取反汇编指令
                    std::string disasm = insn[i].mnemonic;
                    disasm += " ";
                    disasm += insn[i].op_str;

                    // 在基本块中创建 LLVM IR 指令
                    builder.SetInsertPoint(basicBlock);
                    builder.CreateCall(llvm::Intrinsic::getDeclaration(&module, llvm::Intrinsic::dbg_declare), {builder.CreateGlobalStringPtr(disasm)});
                }

                // 释放 Capstone 资源
                cs_free(insn, count);
            }
        }

        this->ld.close_capstone_engine();

        // 输出 LLVM IR 到文件
        std::error_code EC;
        string output_file_name = this->output_file_path + "output.ll";
        llvm::raw_fd_ostream outputFile(output_file_name, EC);
        if (!EC)
        {
            module.print(outputFile, nullptr);
        }
        else
        {
            llvm::errs() << "Failed to open output file for writing\n";
        }

        return basicBlock;
    }
};


#endif // ASSEMBLER_HPP
