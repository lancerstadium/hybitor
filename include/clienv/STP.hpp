#include <string>

using std::string;

/// @brief 子命令`translate`的参数存储类 subcommand_translate_paramters
class STP 
{
public:
    string in_file_path;    // 输入文件路径
    string out_file_path;   // 输出文件路径
    int threads;       // 翻译时，并行最大线程数

    STP() : threads(10) {}  // 构造函数
    ~STP() {} // 析构函数
};