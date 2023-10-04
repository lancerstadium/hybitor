/// \file disassembler.hpp
/// \brief 文件反汇编器以及相关操作

#ifndef DISASSEMBLER_HPP
#define DISASSEMBLER_HPP

// 依赖库
#include <capstone/capstone.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>

// 本地库
#include "core/loader.hpp"
#include "core/writer.hpp"


/// @brief 反汇编器
class disassembler
{


public:
    csh handle;     // Capstone 引擎句柄
    cs_arch arch;   // 文件体系结构
    cs_mode basic;  // 基本模式
    cs_mode extra;  // 额外模式
    loader ld;      // 文件加载器
    writer wt;      // 文件输出器
    // std::unique_ptr<capstone2llvmir::Capstone2LlvmIrTranslator> decorder;     // 译码器

// ------------- disassembler Build 构造操作 ------------- //

    /// @brief 构造函数
    /// @param input_file 输入文件
    /// @param output_path 输出文件路径
    disassembler(string input_file, string output_path) : ld(input_file), wt(output_path){};

    /// @brief 析构函数
    ~disassembler(){};

    // --------- disassembler Capstone 引擎操作 ---------

    /// @brief 初始化Capstone引擎，与 `close_capstone_engine` 结合使用
    /// @param csa 体系结构类型
    /// @param csm 引擎模式
    /// @return 是否成功打开引擎
    bool open_capstone_engine(cs_arch csa, cs_mode csm)
    {
        if (cs_open(csa, csm, &this->handle) != CS_ERR_OK)
        {
            std::cerr << "Failed to initialize Capstone" << std::endl;
            return false;
        }
        return true;
    }

    /// @brief 自动初始化Capstone引擎，与 `close_capstone_engine` 结合使用
    /// @return 是否成功打开引擎
    bool open_capstone_engine()
    {
        parse_bianry_file_header();
        if (cs_open(this->arch, this->basic, &this->handle) != CS_ERR_OK)
        {
            std::cerr << "Failed to initialize Capstone" << std::endl;
            return false;
        }
        return true;
    }

    /// @brief 设置 capstone 引擎选项
    /// @param type 引擎运行时设置类型
    /// @param value 相关值
    void set_cs_option(cs_opt_type type, size_t value)
    {
        cs_option(this->handle, type, value);
    }

    /// @brief 关闭 capstone 引擎，与 `open_capstone_engine` 结合使用
    void close_capstone_engine()
    {
        cs_close(&this->handle);
    }

    /// @brief 设置新的基本模式
    /// @param new_basic_mode 设置新的基本模式
    void set_cs_basic_mode(cs_mode new_basic_mode)
    {
        this->basic = new_basic_mode;
    }

// ------------- disassembler 反汇编接口区 ------------- //

    /// @brief 映射表：解析二进制文件头部，并匹配 arch 和 basic 信息
    void parse_bianry_file_header()
    {
        LIEF::Header header = this->ld.binary->header();
        bool Is_32 = header.is_32();
        bool Is_64 = header.is_64();
        std::set<LIEF::MODES> modes = header.modes();
        /// TODO: 根据 modes 开启 mode
        switch (header.architecture())
        {
        case LIEF::ARCHITECTURES::ARCH_X86:
            this->arch = CS_ARCH_X86;
            if (Is_32) {
                this->basic = CS_MODE_32;
            } else if (Is_64) {
                this->basic = CS_MODE_64;
            } else {
                this->basic = CS_MODE_LITTLE_ENDIAN;
            }
            break;
        case LIEF::ARCHITECTURES::ARCH_MIPS:
            this->arch = CS_ARCH_MIPS;
            if (Is_32) {
                this->basic = CS_MODE_MIPS32;
            } else if (Is_64) {
                this->basic = CS_MODE_MIPS64;
            } else {
                this->basic = CS_MODE_LITTLE_ENDIAN;
            }
            break;
        case LIEF::ARCHITECTURES::ARCH_RISCV:
            this->arch = CS_ARCH_RISCV;
            if (Is_32) {
                this->basic = CS_MODE_RISCV32;
            } else if (Is_64) {
                this->basic = CS_MODE_RISCV64;
            } else {
                this->basic = CS_MODE_LITTLE_ENDIAN;
            }
            break;
        case LIEF::ARCHITECTURES::ARCH_ARM64:
            this->arch = CS_ARCH_ARM64;
            this->basic = CS_MODE_LITTLE_ENDIAN;
            break;
        case LIEF::ARCHITECTURES::ARCH_ARM:
            this->arch = CS_ARCH_ARM;
            this->basic = CS_MODE_ARM;
            break;
        default:
            this->arch = CS_ARCH_ALL;
            this->basic = CS_MODE_LITTLE_ENDIAN;
            break;
        }
    }

    // /// @brief 根据读入文件类型，自动匹配模式，创建译码器
    // /// @param module 
    // void create_decorder(llvm::Module &module)
    // {
    //     this->decorder = capstone2llvmir::Capstone2LlvmIrTranslator::createArch(this->arch, &module, this->basic, this->extra);
    // }


    /// @brief 加载 ELF 文件并反汇编
    /// @return 错误信息
    bool load_and_disassemble_file()
    {
        // 1. 解析二进制文件
        if (!this->ld.parse_binary_file())
        {
            return false;
        }
        // 2. 初始化 Capstone 引擎
        this->open_capstone_engine();
        // 3. 设置反汇编选项
        this->set_cs_option(CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
        // 4. 打印反汇编ELF文件内容
        this->print_disassemble_file();
        // 5. 关闭 Capstone 引擎
        this->close_capstone_engine();
        return true;
    }

    bool write_to_asm_file()
    {
        // 1. 解析输入二进制文件
        if (!this->ld.parse_binary_file())
        {
            return false;
        }
        // 2.初始化asm输出文件流
        if (!this->wt.open_output_asm_file())
        {
            return false;
        }
        // 3. 初始化 Capstone 引擎
        this->open_capstone_engine();
        // 4. 设置反汇编选项
        this->set_cs_option(CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
        // 5. 反汇编写入汇编文件
        this->write_in_assemble_file();
        // 6. 关闭asm输出文件流
        this->wt.close_output_asm_file();
        // 7. 关闭 Capstone 引擎
        this->close_capstone_engine();
        return true;
    }
private:

// ------------- disassembler 反汇编操作区 ------------- //

    /// @brief 打印反汇编后的二进制文件信息
    /// @return 错误信息
    int print_disassemble_file()
    {
        cs_insn *insn; // 存储反汇编指令
        size_t count;  // 反汇编指令个数
        for (const auto &section : this->ld.binary->sections())
        {
            if (section.content().empty())
            {
                continue;
            }
            count = cs_disasm(this->handle, section.content().data(), section.content().size(), section.virtual_address(), 0, &insn);
            if (count > 0)
            {
                for (size_t i = 0; i < count; ++i)
                {
                    // 打印反汇编指令
                    printf("0x%" PRIx64 ": %s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
                }
                // 释放 Capstone 资源
                cs_free(insn, count);
            }
        }
        return 0;
    }

    /// @brief 写入汇编文件
    /// @return 错误信息
    int write_in_assemble_file()
    {
        cout << "Writting ..." << endl;
        cs_insn *insn; // 存储反汇编指令
        size_t count;  // 反汇编指令个数
        for (const auto &section : this->ld.binary->sections())
        {
            if (section.content().empty())
            {
                continue;
            }
            this->wt.asm_file << "Section :" << section.name() << std::endl;

            count = cs_disasm(this->handle, section.content().data(), section.content().size(), section.virtual_address(), 0, &insn);
            if (count > 0)
            {
                for (size_t i = 0; i < count; ++i)
                {
                    // 输出到文件  
                    this->wt.asm_file << "0x" << std::hex << insn[i].address << ": " << insn[i].mnemonic << " " << insn[i].op_str << std::endl;
                }
                cout << "Section [" << section.name()  << "] writting to file: " << this->wt.final_output_file << endl;
                // 释放 Capstone 资源
                cs_free(insn, count);
            }
        }
        return 0;
    }

};

#endif // DISASSEMBLER_HPP
