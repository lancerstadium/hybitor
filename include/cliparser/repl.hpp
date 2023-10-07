/// \file repl.hpp
/// \brief 子命令 repl 的数据存储和业务实现

#ifndef REPL_HPP
#define REPL_HPP

#include "core/repler.hpp"

// @brief 子命令`lift的参数存储类 subcommand_lift_paramters
class SRP 
{
public:
    string in_file_path;    // 输入文件路径
    string out_file_path;   // 输出文件路径
    string Default_OLFP = "./output.ll";  // 默认输出路径 default_output_lift_file_path

    /// @brief 构造函数
    SRP() {}

    ~SRP() {} // 析构函数


    /// @brief 打印 lift 解析后的输入参数
    void print_parsed_parameters()
    {
        cout<<"Input file: "<<this->in_file_path<<endl;
        cout<<"Output file: "<<this->out_file_path<<endl;
    }

    /// @brief 执行 repl 主业务：进入主界面
    /// @return 错误信息
    void command_exec()
    {
        repler rp;
        rp.enter_repl();
    }

};


#endif // REPL_HPP