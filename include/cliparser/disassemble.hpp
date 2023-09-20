/// \file disassemble.hpp
/// \brief 子命令 disassemble 的数据存储和业务实现

#ifndef DISASSEMBLE_HPP
#define DISASSEMBLE_HPP

// 本地库
#include "binaryfile/loader.hpp"


// @brief 子命令`disassemble`的参数存储类 subcommand_disassemble_paramters
class SDP 
{
public:
    string in_file_path;    // 输入文件路径
    string out_file_path;   // 输出文件路径

    SDP() {}  // 构造函数
    ~SDP() {} // 析构函数


    /// @brief 打印 translate 解析后的输入参数
    void print_parsed_parameters()
    {
        cout<<"Input file: "<<this->in_file_path<<endl;
        cout<<"Output file: "<<this->out_file_path<<endl;
    }

    /// @brief 执行 disassemble 主业务
    /// @return 错误信息
    void command_exec()
    {
        loader ld = loader(this->in_file_path);
        ld.load_disassemble_file();
    }

};

#endif // DISASSEMBLE_HPP