/// \file core/repler.hpp
/// \brief 交互界面 REPL 实现

#ifndef REPLER_HPP
#define REPLER_HPP

#include "emulator/machine.hpp"
#include "core/lifter.hpp"


/// @brief REPL 类
class repler
{
private:
    
public:

    string repl_command; // 命令字符串
    std::vector<string> hist_commands; // 历史命令
    VM vm;  // 虚拟机
    char img_path[500];        // 文件名

    repler() {
        
    }
    ~repler() {}

    /// @brief command c: 执行程序
    void cmd_c()
    {
        this->vm.VM_exec();
    }

    /// @brief command h: 帮助信息
    void cmd_h() {
        cout << "[Commands]: " << endl;
        cout << "   q: quit" << endl;
        cout << "   c: run" << endl;
        cout << "   r [path]: read .bin file from path to memory" << endl;
        cout << "   s: exec once" << endl;
        cout << "   p [addr]: set breakpoint at addr" << endl;
        cout << "   t: riscv-tests" << endl;
        cout << "   h: help" << endl;
    }

    void cmd_re()
    {
        todo("cmd_re");
    }

    void cmd_r()
    {
        scanf("%s", img_path);
        FILE *fp = fopen(img_path, "rb");
        assert(fp);
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        printf("Read %ld byte from file.\n", size);
        fseek(fp, 0, SEEK_SET);
        fread(this->vm.cpu.bus.dram.dram + RESET_VECTOR_OFFSET, size, 1, fp);
        fclose(fp);
    }

    void cmd_si()
    {
        todo("cmd_si");
    }

    void cmd_s()
    {
        this->vm.VM_cpu_exec_once();
    }

    void cmd_p()
    {
        todo("cmd_p");
    }

    void cmd_t()
    {
        todo("cmd_t");
    }

    

    /// @brief 进入 REPL 调试环境
    int enter_repl() {
        cout << "[Hybitor REPL Mode]: " << endl;
        while (1) {
            cout << "> ";
            std::cin >> repl_command;
            switch (repl_command[0]) {
                case 'q':
                    cout << "Bye, nice day!" << endl;
                    return 0;
                case 'c':
                    cmd_c();
                    break;
                case 'h':
                    cmd_h();
                    break;
                case 'r':
                    if (repl_command[1] == 'e') cmd_re();
                    else cmd_r();
                    break;
                case 's':
                    if (repl_command[1] == 'i') {
                        cmd_si();
                    } else cmd_s();
                    break;
                case 'p':
                    cmd_p();
                    break;
                case 't':
                    cmd_t();
                    break;
                default:
                    puts("invalid command");
                    puts("input \'h\' for help");
                    break;
            }
        }
        return 0;
    }


};



#endif // REPLER_HPP

