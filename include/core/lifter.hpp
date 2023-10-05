/// \file lifter.hpp
/// \brief 提升器以及相关操作

#ifndef LIFTER_HPP
#define LIFTER_HPP

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

// 本地库
#include "core/loader.hpp"
#include "core/writer.hpp"
#include "core/disassembler.hpp"
#include "cpu/cpu.hpp"
#include "insn/syscall.hpp"
#include "tools/debug.hpp"


/// @brief 反汇编器
class lifter
{
private:
public:
    disassembler das;   // 反汇编器

    /// @brief 构造函数
    /// @param input_file 输入文件
    /// @param output_path 输出文件路径
    lifter(string input_file, string output_file) : das(input_file, output_file) {};

    /// @brief 析构函数
    ~lifter(){};

    // --------- test --------- //
    void interp_exec(int argc, char* argv[])
    {
        VM vm;
        // vm.VM_setup(argc, argv);
        vm.VM_load_program(this->das.ld);
        vm.VM_exec_program();
        while(true) {
            // 执行指令
            enum exit_reason_t reason = vm.VM_exec_program();
            assert(reason == ecall);
            // 获取系统调用编号：存储在通用寄存器 a7 里
            u64 syscall = vm.get_gp_reg(a7);
            // 执行系统调用
            u64 ret = do_syscall(vm, syscall);
            // 保存系统调用返回值：返回到通用寄存器 a0 里
            vm.set_gp_reg(a0, ret);
        }

    }


    // --------- lifter 功能区 --------- //

    /// @brief 将二进制文件提升到LLVM IR，并生成.ll文件
    /// @return 
    int lift_to_ll_file()
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

    /// @brief 解析二进制文件并将其装载成基本块
    /// @param context llvm 上下文
    /// @return llvm BasicBlock 指针
    llvm::BasicBlock *loadBinaryToBlock(llvm::LLVMContext &context)
    {
        // 1. 创建一个新的 LLVM 模块和函数
        llvm::Module module("MyModule", context);
        llvm::IRBuilder<> builder(context);

        llvm::FunctionType *funcType = llvm::FunctionType::get(builder.getVoidTy(), false);
        llvm::Function *function = llvm::Function::Create(funcType, llvm::Function::ExternalLinkage, "myFunction", module);
        llvm::BasicBlock *basicBlock = llvm::BasicBlock::Create(context, "entry", function);

        // 2. 解析 loader 内的二进制文件
        this->das.ld.parse_binary_file();

        // 3. 打开 Capstone 引擎
        this->das.open_capstone_engine();

        // 4. 使用 Capstone 反汇编并将指令添加到基本块
        cs_insn *insn;
        size_t count;
        for (const auto &section : this->das.ld.binary->sections())
        {
            if (section.content().empty())
            {
                continue;
            }
            count = cs_disasm(this->das.handle, section.content().data(), section.content().size(), section.virtual_address(), 0, &insn);
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

        // 5. 关闭 Capstone 引擎
        this->das.close_capstone_engine();

        // 6. 输出 LLVM IR 到文件
        this->das.wt.output_to_ll_file(module);

        return basicBlock;
    }
};


#endif // LIFTER_HPP
