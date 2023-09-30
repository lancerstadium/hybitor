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
using std::cerr;
using std::cout;
using std::endl;
using std::string;

/// @brief 二进制 ELF 文件加载器类
class loader
{
private:
public:
    string input_file_name;               // 待解析二进制文件名
    std::unique_ptr<LIEF::Binary> binary; // 二进制文件
    LIEF::OBJECT_TYPES type;              // 二进制文件类型

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
        try
        {
            // 解析二进制文件
            this->binary = LIEF::Parser::parse(this->input_file_name);
            this->type = this->binary->header().object_type();
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error parsing binary: " << e.what() << std::endl;
            return false;
        }
        return true;
    }

    /// @brief 打印二进制文件信息
    void print_binary_file()
    {
        // 打印文件头信息
        std::cout << "[File Header]:" << std::endl;
        std::cout << binary->header() << std::endl;

        // 打印节头信息
        std::cout << "[Section Headers]:" << std::endl;
        for (auto &section : binary->sections())
        {
            std::cout << "Section: " << section.name() << std::endl;
            std::cout << "Address: " << std::hex << section.virtual_address() << std::endl;
            std::cout << "Size: " << std::dec << section.size() << " bytes" << std::endl;
        }

    }
};

#endif // LOADER_HPP
