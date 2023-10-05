/// \file main.cpp
/// \brief 接收并解析命令行参数，加载合适的 libtinycode-*.so

// 标准库
#include <iostream>


// 本地库
#include "cliparser/cliparser.hpp"

// 引用
using std::cout;
using std::string;
using std::endl;


// 主程序入口
int main(int argc, char **argv)
{
    // --- 解析执行输入参数 ---
    cliparser cp;                      
    cp.cli_init();              // 初始化 CLI 环境
    cp.cli_parse(argc, argv);   // 解析参数
    cp.cli_exec(argc, argv);    // CLI 执行命令

	return 0;
}