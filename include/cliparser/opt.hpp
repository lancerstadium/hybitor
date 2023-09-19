/// \file opt.hpp
/// \brief 子命令 opt 的数据存储和业务实现

#ifndef OPT_HPP
#define OPT_HPP

#include <iostream>
#include <string>

using std::string;
using std::cout;
using std::endl;

/// @brief 子命令`opt`的参数存储类 subcommand_opt_paramters
class SOP 
{
public:
    string in_file_path;    // 输入文件路径
    string out_file_path;   // 输出文件路径

    SOP() {}  // 构造函数
    ~SOP() {} // 析构函数

    /// @brief 打印 opt 解析后的输入参数
    void print_parsed_parameters()
    {
        cout<<"Input file: "<<in_file_path<<endl;
        cout<<"Output file: "<<out_file_path<<endl;
    }

    void command_exec()
    {
        
    }
};

#endif // OPT_HPP