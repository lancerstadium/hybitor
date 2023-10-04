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
#include <LIEF/LIEF.hpp>


// 引用
using std::cout;
using std::endl;
using std::string;
using std::cerr;

/// @brief 二进制 ELF 文件加载器类
class loader
{
private:
    

public:

    string input_file_name;   // 待解析二进制文件名
    std::unique_ptr<LIEF::Binary> binary;  // 二进制文件
    LIEF::OBJECT_TYPES type;    // 二进制文件类型

    std::unique_ptr<LIEF::ELF::Binary> elf; // elf 文件
    LIEF::ELF::E_TYPE e_type;   // elf文件类型

    std::unique_ptr<LIEF::MachO::FatBinary> macho; // macho 文件
    LIEF::MachO::FILE_TYPES m_type; // macho文件类型
    

    // --------- loader build 构造&析构区 ---------

    /// @brief 构造函数
    loader() {} // 构造函数

    /// @brief 构造函数
    /// @param filename 输入文件名
    loader(string filename) : input_file_name(filename) {}

    /// @brief 析构函数
    ~loader() {}


    // --------- loader fileIO 文件操作 ---------

    /// @brief 读入并解析二进制文件
    /// @return 是否成功解析二进制文件
    bool parse_binary_file() 
    {
        try {
            // 解析二进制文件
            this->binary = LIEF::Parser::parse(this->input_file_name);
            this->type = this->binary->header().object_type();

        } catch (const std::exception& e) {
            std::cerr << "Error parsing binary: " << e.what() << std::endl;
            return false;
        }
        return true;
    }

    /// @brief 读入并解析 ELF 文件
    /// @return 是否成功解析elf文件
    std::unique_ptr<LIEF::ELF::Binary> parse_elf_file() 
    {
        // 解析elf文件
        return LIEF::ELF::Parser::parse(this->input_file_name);
    }

    /// @brief 读入并解析 macho 文件
    /// @return 是否成功解析 macho 文件
    std::unique_ptr<LIEF::MachO::FatBinary> parse_macho_file() 
    {
        // 解析macho文件
        return LIEF::MachO::Parser::parse(this->input_file_name);
    }


    
};

#endif // LOADER_HPP
