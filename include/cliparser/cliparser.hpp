/// \file cliparser.h
/// \brief 命令行子命令的业务路由与参数存储

// 本地库
#include "CLI11.hpp"
#include "STP.hpp"
#include "SOP.hpp"



// 预定义
#define CLI_PARSE_SUCCESS 1     // 成功解析输入参数

// 引用
using std::cout;
using std::string;
using std::endl;


// hybitor 软件描述：CLI第一行
static string app_describe = "[hybitor] - a hybird binary translator based on Qemu and LLVM.\n[Developer]: Lancer\n[Email]: lancerstadium@163.com\n[Repository]: https://github.com/lancerstadium/hybitor.git\n";


/// @brief 存储输入参数的 CLI 解析器
class cliparser {
public:
    CLI::App app{app_describe};     // CLI 软件对象
    STP stp;   // 子命令的参数存储对象 subcommand_paramters
    SOP sop;

    cliparser() {}   // 构造函数
    ~cliparser() {}                // 析构函数

    /// @brief CLI 初始化软件信息
    /// @return 
    void cli_init()
    {
        // hybitor 软件备注：CLI最后一行
        this->app.footer("");
        this->app.get_formatter()->column_width(40);  // 列宽
        this->app.require_subcommand(0, 1);           // 表示程序子命令个数为0～1

        // --- CLI子命令设置 ---
        // hybitor translate : 输入可执行ELF文件进行翻译，输出Host端可执行ELF文件。
        auto subcommand_hello = this->app.add_subcommand("hello", "Say `Hello` to user\n和用户打招呼\n");
        auto subcommand_translate = this->app.add_subcommand("translate", "Translate ELF file to host architecture\n翻译可执行ELF文件到Host端\n");
        auto subcommand_opt = this->app.add_subcommand("opt", "Optimizate .ll or .bc (LLVM IR)file\n优化LLVM中间表示文件\n");
        // 当出现的参数子命令解析不了时,尝试返回上一级主命令解析
        subcommand_hello->fallthrough();
        subcommand_translate->fallthrough(); 
        subcommand_opt->fallthrough();   

        // 0.如果执行`hello`子命令，则检查参数
        if(subcommand_hello)
        {

        }
        // 1.如果执行`translate`子命令，则检查参数
        if(subcommand_translate)
        {
            // 初始化子命令参数
            this->stp = STP();    // *修改这里*：子命令`translate`的参数存储对象  
            // 检查输入文件是否存在，必选参数
            subcommand_translate->add_option("file", this->stp.in_file_path, "Input file path 输入文件路径")->check(CLI::ExistingFile)->required();
            // 检查线程参数必须大于0
            subcommand_translate->add_option("-n,-N", this->stp.threads, "Set thread number 设置线程数")->check(CLI::PositiveNumber);
            // 检查输出文件目录是否存在
            subcommand_translate->add_option("-o", this->stp.out_file_path, "Output file path 输出文件路径")->check(CLI::ExistingDirectory);
        }
        // 2.如果执行`opt`子命令，则检查参数
        if(subcommand_opt)
        {
            // 初始化子命令参数
            this->sop = SOP();    // *修改这里*：子命令`opt`的参数存储对象  
            // 检查输入文件是否存在，必选参数
            subcommand_opt->add_option("file", this->sop.in_file_path, "Input file path 输入文件路径")->check(CLI::ExistingFile)->required();
            // 检查输出文件目录是否存在
            subcommand_opt->add_option("-o", this->sop.out_file_path, "Output file path 输出文件路径")->check(CLI::ExistingDirectory);
        }
    }

    /// @brief CLI 解析输入命令参数
    /// @param argc `main()` 读入参数个数
    /// @param argv `main()` 读入参数数组
    /// @return int 错误信息
    int cli_parse(int argc, char **argv)
    {
        CLI11_PARSE(app, argc, argv);

        return CLI_PARSE_SUCCESS;
    }
    

    /// @brief CLI 执行触发事件（业务）
    void cli_exec()
    {
        // --- CLI 子命令触发事件 ---
        // 0.触发`hello`
        auto subcommand_hello = this->app.get_subcommand("hello");
        if(subcommand_hello->parsed())
        {
            cout<<"Hello, welcome to hypitor!"<<endl;
        }
        // 1.触发`translate`
        auto subcommand_translate = this->app.get_subcommand("translate");
        if(subcommand_translate->parsed())
        {
            cout<<"Input file: "<<this->stp.in_file_path<<endl;
            cout<<"Output file: "<<this->stp.out_file_path<<endl;
            cout<<"Threads: "<<this->stp.threads<<endl;
            // TODO: load_binary_file(STP stp)
        }
        // 2.触发`opt`
        auto subcommand_opt = this->app.get_subcommand("opt");
        if(subcommand_opt->parsed())
        {
            cout<<"Input file: "<<this->sop.in_file_path<<endl;
            cout<<"Output file: "<<this->sop.out_file_path<<endl;
        }
    }

}; // class cliparser











