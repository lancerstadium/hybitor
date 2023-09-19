/// \file translate.hpp
/// \brief 子命令 translate 的数据存储和业务实现


// 本地库
#include "binaryfile/loader.hpp"


// @brief 子命令`translate`的参数存储类 subcommand_translate_paramters
class STP 
{
public:
    string in_file_path;    // 输入文件路径
    string out_file_path;   // 输出文件路径
    int threads;       // 翻译时，并行最大线程数

    STP() : threads(10) {}  // 构造函数
    ~STP() {} // 析构函数


    /// @brief 打印 translate 解析后的输入参数
    void print_parsed_parameters()
    {
        cout<<"Input file: "<<this->in_file_path<<endl;
        cout<<"Output file: "<<this->out_file_path<<endl;
        cout<<"Threads: "<<this->threads<<endl;
    }

    /// @brief 执行 translate 主业务
    /// @return 错误信息
    void command_exec()
    {
        loader ld = loader(this->in_file_path);
        ld.load_elf_file();
    }

};