#include <string>

using std::string;

/// @brief 子命令`opt`的参数存储类 subcommand_opt_paramters
class SOP 
{
public:
    string in_file_path;    // 输入文件路径
    string out_file_path;   // 输出文件路径

    SOP() {}  // 构造函数
    ~SOP() {} // 析构函数
};