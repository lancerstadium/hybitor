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
    std::__1::unique_ptr<LIEF::Binary> binary;  // 二进制文件
    

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
    bool parse_binary_file() {
        try {
            // 解析二进制文件
            this->binary = LIEF::Parser::parse(this->input_file_name);

        } catch (const std::exception& e) {
            std::cerr << "Error parsing binary: " << e.what() << std::endl;
            return false;
        }
        return true;
    }
    
};

#endif // LOADER_HPP
