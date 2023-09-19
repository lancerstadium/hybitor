
#include <iostream>
#include <vector>
#include <string>
#include <fstream>


// 依赖库
#include <capstone/capstone.h>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

using std::string;
using std::cout;
using std::endl;

/// @brief 二进制 ELF 文件加载器类
class loader
{
private:
    string elf_file_name;
    csh handle;

    /// @brief 初始化Capstone引擎
    /// @return 错误信息
    int open_capstone_engine()
    {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &this->handle) != CS_ERR_OK) {
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

public:
    /// @brief 构造函数
    loader() {} // 构造函数

    /// @brief 构造函数
    /// @param filename 输入文件名
    loader(string filename) : elf_file_name(filename) {}   

    /// @brief 析构函数
    ~loader() {}

    // ----- loader 功能区 -----

    /// @brief 加载 ELF 文件并反汇编
    /// @return 
    int load_elf_file()
    {
        // 1. 打开ELF文件
        std::ifstream elf_file(elf_file_name, std::ios::binary | std::ios::ate);
        if (!elf_file.is_open()) {
            std::cerr << "Failed to open ELF file: " << elf_file_name << std::endl;
            return -1;
        }

        // 2. 获取ELF文件大小
        std::streamsize elf_file_size = elf_file.tellg();
        elf_file.seekg(0);

        // 3. 读取ELF文件内容
        std::vector<char> elf_data(elf_file_size);
        if (!elf_file.read(elf_data.data(), elf_file_size)) {
            std::cerr << "Failed to read ELF file: " << elf_file_name << std::endl;
            return -1;
        }
        // 4. 初始化Capstone引擎
        open_capstone_engine();
        // 5. 设置反汇编选项
        cs_option(this->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

        // 6. 反汇编ELF文件内容
        cs_insn *insn;
        size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(elf_data.data()), elf_data.size(), 0, 0, &insn);
        if (count > 0) {
            for (size_t i = 0; i < count; ++i) {
                printf("0x%" PRIx64 ": %s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
            }
            cs_free(insn, count);
        } else {
            std::cerr << "Failed to disassemble ELF file" << std::endl;
        }

        // 7. 关闭Capstone引擎
        close_capstone_engine();
        return 0;
    }

    // ----- loader 测试区 -----

    /// @brief x86反汇编测试
    /// @return 错误信息
    int asm_x86_test()
    {

        open_capstone_engine();

        cs_insn *insn;
        size_t count;

        count = cs_disasm(this->handle, (uint8_t *)CODE, sizeof(CODE) - 1, 0x1000, 0, &insn);
        if (count > 0)
        {
            size_t j;
            for (j = 0; j < count; j++)
            {
                printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            }
            cs_free(insn, count);
        }
        else
            printf("ERROR: Failed to disassemble given code!\n");

        close_capstone_engine();
        return 0;
    }


    
};
