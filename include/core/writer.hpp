/// \file writer.hpp
/// \brief 文件写入器以及相关操作

#ifndef WRITER_HPP
#define WRITER_HPP

// 本地库
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

// 依赖库


// 引用
using std::cout;
using std::endl;
using std::string;
using std::cerr;

/// @brief 二进制 ELF 文件加载器类
class writer
{
private:
    
    string output_file_name;    // 输出文件名
    string output_file_path;    // 输出文件路径
    
    

    /// @brief 设置最终输出文件
    void parse_output_file()
    {
        this->final_output_file = this->output_file_path + this->output_file_name;
    }

public:
    string final_output_file;   // 最终输出文件
    std::ofstream asm_file;     // 汇编文件流

    // --------- writer build 构造&解构区 ---------
    writer() {}
    writer(string file_name) : output_file_name(file_name), output_file_path("") 
    {
        parse_output_file();
    }
    ~writer() {}


    // --------- writer filename 文件名设置 ---------

    /// @brief 设置输出文件名
    void set_output_file_name()
    {
        parse_output_file();
    }

    /// @brief 设置输出文件名
    /// @param new_file 新的输出文件名
    void set_output_file_name(string new_file)
    {
        this->output_file_name = new_file;
        parse_output_file();
    }



    // --------- writer asmmebler 汇编文件操作 ---------
    
    /// @brief 初始化写入汇编文件流，与 `close_output_asm_file` 结合使用
    /// @return 
    bool open_output_asm_file()
    {
        // 设置并打开 asm 文件
        set_output_file_name();
        asm_file = std::ofstream(this->final_output_file);
        if (!asm_file.is_open()) {
            std::cerr << "Failed to open the output assembly file." << std::endl;
            return false;
        }
        return true;
    }

    /// @brief 关闭写入汇编文件流，与 `open_output_asm_file` 结合使用
    void close_output_asm_file()
    {
        asm_file.close();
    }
    

    // --------- writer llvm ir 中间码文件操作---------

    /// @brief 输出 LLVM IR 到文件
    /// @param module llvm Module 模块
    int output_to_ll_file(llvm::Module &module)
    {
        set_output_file_name();
        std::error_code EC;
        llvm::raw_fd_ostream ll_file(this->output_file_name, EC);
        if (!EC)
        {
            cout << "Success to output file in: " << this->final_output_file << endl;
            module.print(ll_file, nullptr);
            return 0;
        }
        else
        {
            llvm::errs() << "Failed to open output file for writing\n";
            return -4;
        }
    }



    /// @brief 输出 LLVM IR 到文件
    /// @param module llvm 模块
    /// @param new_file 新文件名
    /// @return 错误信息
    int output_to_ll_file(llvm::Module module, string new_file)
    {
        set_output_file_name(new_file);
        std::error_code EC;
        llvm::raw_fd_ostream ll_file(this->final_output_file, EC);
        if (!EC)
        {
            cout << "Successfully written to file: " << new_file << endl;
            module.print(ll_file, nullptr);
            return 0;
        }
        else
        { 
            llvm::errs() << "Failed to open output file for writing\n";
            return -4;
        }
    }

};

#endif // WRITER_HPP
