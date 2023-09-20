/// \file loader.hpp
/// \brief 文件加载器以及相关操作

#ifndef LOADER_HPP
#define LOADER_HPP

// 本地库
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

// 依赖库
#include <capstone/capstone.h>
// #include <elfio/elfio.hpp>


// using namespace ELFIO;

using std::cout;
using std::endl;
using std::string;
using std::cerr;

/// @brief 二进制 ELF 文件加载器类
class loader
{
private:
    std::ifstream elf_file;
    std::streamsize elf_file_size;
    std::vector<char> elf_data;
    

public:

    string elf_file_name;
    csh handle;

    /// @brief 构造函数
    loader() {} // 构造函数

    /// @brief 构造函数
    /// @param filename 输入文件名
    loader(string filename) : elf_file_name(filename) {}

    /// @brief 析构函数
    ~loader() {}


    // ----- loader 工具函数区 -----

    /// @brief 初始化Capstone引擎
    /// @param csa 体系结构类型
    /// @param csm 引擎模式
    /// @return 错误信息
    int open_capstone_engine(cs_arch csa, cs_mode csm)
    {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &this->handle) != CS_ERR_OK)
        {
            std::cerr << "Failed to initialize Capstone" << std::endl;
            return -1;
        }
        return 0;
    }

    /// @brief 关闭 capstone 引擎
    void close_capstone_engine()
    {
        cs_close(&this->handle);
    }

    // --------- loader 业务区 ---------

    /// @brief 加载 ELF 文件并反汇编
    /// @return
    int load_disassemble_file()
    {
        // 1. 打开ELF文件
        open_file();
        // 2. 初始化 Capstone 引擎
        open_capstone_engine(CS_ARCH_X86, CS_MODE_64);
        // 3. 设置反汇编选项
        cs_option(this->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        cs_insn *insn;  // 设置 capstone 指令存储
        // 4. 反汇编ELF文件内容
        disassemble_file(insn);
        // 5. 关闭文件流
        close_file();
        // 6. 关闭 Capstone 引擎
        close_capstone_engine();
        return 0;
    }





    // --------- loader 功能区 ---------

    /// @brief 打开文件流
    /// @return 错误信息
    int open_file() 
    {
        // 1. 访问文件路径
        this->elf_file = std::ifstream(this->elf_file_name, std::ios::binary | std::ios::ate);
        if (!this->elf_file.is_open())
        {
            cerr << "Failed to open ELF file: " << this->elf_file_name << endl;
            return -1;
        }

        // 2. 获取ELF文件大小
        this->elf_file_size = this->elf_file.tellg();
        this->elf_file.seekg(0);

        // 3. 读取ELF文件内容
        this->elf_data = std::vector<char>(this->elf_file_size);
        if (!this->elf_file.read(this->elf_data.data(), this->elf_file_size))
        {
            cerr << "Failed to read ELF file: " << this->elf_file_name << endl;
            return -2;
        }
        return 0;
    }

    /// @brief 关闭文件流
    void close_file()
    {
        this->elf_file.close();
    }



    int disassemble_file(cs_insn *insn)
    {
        size_t count = cs_disasm(this->handle, reinterpret_cast<const uint8_t *>(this->elf_data.data()), this->elf_data.size(), 0, 0, &insn);
        if (count > 0)
        {
            for (size_t i = 0; i < count; ++i)
            {
                printf("0x%" PRIx64 ": %s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
            }
            cs_free(insn, count);
        }
        else
        {
            cerr << "Failed to disassemble ELF file" << endl;
            return -3;
        }
        return 0;
    }


    // /// @brief 使用 ELFIO 加载 ELF 文件，并打印文件基本信息
    // /// @return
    // int load_elf_file_by_elfio()
    // {
    //     // 1. 打开ELF文件
    //     elfio reader;   // 创建 ELFIO 文件加载器
    //     if (!reader.load(this->elf_file_name))
    //     {
    //         std::cerr << "Failed to open ELF file: " << elf_file_name << std::endl;
    //         return -1;
    //     }
        

    //     std::cout << "Machine: " << reader.get_machine() << std::endl;
        
    //     // 2. 



    //     // 2. 打印 ELF 文件属性
    //     std::cout << "ELF file class    : ";
    //     if (reader.get_class() == ELFCLASS32)
    //         std::cout << "ELF32" << std::endl;
    //     else
    //         std::cout << "ELF64" << std::endl;

    //     std::cout << "ELF file encoding : ";
    //     if (reader.get_encoding() == ELFDATA2LSB)
    //         std::cout << "Little endian" << std::endl;
    //     else
    //         std::cout << "Big endian" << std::endl;

    //     // 3. 打印 ELF 文件 sections 信息
    //     Elf_Half sec_num = reader.sections.size();          
    //     std::cout << "Number of sections: " << sec_num << std::endl; 
    //     for ( int i = 0; i < sec_num; ++i ) { 
    //         const section* psec = reader.sections[i];       
    //         std::cout << "  [" << i << "] " 
    //                 << psec->get_name()  
    //                 << "\t"
    //                 << psec->get_size()
    //                 << std::endl; 
    //         // Access section's data 
    //         const char* p = reader.sections[i]->get_data();  
    //     } 

    //     // 4. 打印 ELF 文件 segments 信息
    //     Elf_Half seg_num = reader.segments.size();          
    //     std::cout << "Number of segments: " << seg_num << std::endl; 
    //     for ( int i = 0; i < seg_num; ++i ) { 
    //         const segment* pseg = reader.segments[i];       
    //         std::cout << "  [" << i << "] 0x" << std::hex 
    //                 << pseg->get_flags()                  
    //                 << "\t0x"
    //                 << pseg->get_virtual_address()        
    //                 << "\t0x"
    //                 << pseg->get_file_size()              
    //                 << "\t0x"
    //                 << pseg->get_memory_size()            
    //                 << std::endl;
    //         // Access segments's data 
    //         const char* p = reader.segments[i]->get_data(); 
    //     }

    //     return 0;
    // }

    // --------- loader 测试区 ---------
};

#endif // LOADER_HPP
