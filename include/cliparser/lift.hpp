/// \file lift.hpp
/// \brief 子命令 lift 的数据存储和业务实现

#ifndef LIFT_HPP
#define LIFT_HPP


#include "core/lifter.hpp"



// @brief 子命令`lift的参数存储类 subcommand_lift_paramters
class SLP 
{
public:
    string in_file_path;    // 输入文件路径
    string out_file_path;   // 输出文件路径
    string Default_OLFP = "./output.ll";  // 默认输出路径 default_output_lift_file_path

    /// @brief 构造函数
    SLP() {}

    ~SLP() {} // 析构函数


    /// @brief 打印 lift 解析后的输入参数
    void print_parsed_parameters()
    {
        cout<<"Input file: "<<this->in_file_path<<endl;
        cout<<"Output file: "<<this->out_file_path<<endl;
    }

    /// @brief 执行 lift 主业务：Guest指令提升到 LLVM IR
    /// @return 错误信息
    void command_exec(int argc, char* argv[])
    {
        lifter lt(this->in_file_path, this->out_file_path);
        // lt.lift_to_ll_file();
        lt.interp_exec(argc, argv);

    }

};

#endif // LIFT_HPP