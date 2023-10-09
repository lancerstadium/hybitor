/// \file emulator/machine.hpp
/// \brief RISC-V64 machine 模拟

#ifndef EMULATOR_MACHINE_HPP
#define EMULATOR_MACHINE_HPP


#include "emulator/interpreter.hpp"
#include "emulator/syscall.hpp"


class VM
{
private:

public:

    CPU cpu;
    u64 p_addr;         // 物理地址
    interpreter it;     // 解释器


    /// @brief 虚拟机初始化
    VM() {
        this->cpu.cpu_init();
        // this->it.init_inst_func();
    }
    ~VM() {}



    /// @brief 虚拟机加载文件
    /// @param img_path 文件路径
    void VM_load_file(string img_path)
    {
        int fd = open(img_path.c_str(), O_RDONLY); // 只读打开文件
        if (fd == -1)
        { // 文件名错误：输出错误信息
            fatal(strerror(errno));
        }
        this->cpu.bus.dram.mem_load_elf(fd);
        close(fd);
        this->cpu.pc = this->cpu.bus.dram.entry;
    }


    /// @brief 虚拟机执行程序
    void VM_exec()
    {
        this->cpu.state = CPU::CPU_RUN;
        this->VM_cpu_exec(-1);
    }

    /// @brief CPU 执行
    /// @param n CPU 执行次数：-1代表无穷
    void VM_cpu_exec(u32 n)
    {
        for (int i = 0; i < n; i++) {
            if (this->cpu.state == CPU::CPU_RUN)
                VM_cpu_exec_once();
            else break;
        }
    }

    /// @brief CPU 执行一次
    void VM_cpu_exec_once_v2()
    {
        // this->cpu.regs[CPU::zero] = 0;
        // if (this->cpu.pc == p_addr) {
        //     this->cpu.state = CPU::CPU_STOP; // 放置于停止状态
        //     printf("breakpoint at 0x%lx\n", (unsigned long)p_addr);
        //     p_addr = -1;
        //     return;
        // }
        // u32 data = this->cpu.cpu_fetch_inst();
        // printf("inst = 0x%08x\n", data);

        // this->it.dc.set_decoder(data);
        // if (this->it.dc.inst_name == (int)INST_NAME::INST_NUM) {
        //     this->cpu.state = CPU::CPU_STOP;
        //     printf("* Hybitor REPL Stop, Error Info: \n");
        //     printf("* PC = 0x%08lx inst=0x%08x inst_name = %d\n", (unsigned long)this->cpu.pc, data, this->it.dc.inst_name);
        //     todo("Unsupported instruction or EOF");
        //     return;
        // }

        // this->it.dc.dnpc = this->it.dc.snpc = this->cpu.pc + 4;
        // this->it.cpu = this->cpu;
        // this->it.interp_exec_inst(this->cpu);
        // this->cpu.pc = this->it.dc.dnpc;
    }

    /// @brief CPU 执行一次 version2
    void VM_cpu_exec_once()
    {
        this->cpu.regs[CPU::zero] = 0;
        this->cpu.exit_reason = CPU::none;

        if (this->cpu.pc == p_addr) {
            this->cpu.state = CPU::CPU_STOP; // 放置于停止状态
            printf("breakpoint at 0x%lx\n", (unsigned long)p_addr);
            p_addr = -1;
            return;
        }

        u32 data = this->cpu.cpu_fetch_inst();
        static insn_t insn = {0};
        this->it.dc.insn_decode(&insn, data);
        funcs[insn.type](this->cpu, &insn);

        // 处理跳转事件
        if(this->cpu.exit_reason == CPU::indirect_branch || this->cpu.exit_reason == CPU::direct_branch)
        {
            this->cpu.pc = this->cpu.reenter_pc;
            printf("inst = 0x%08x, pc = 0x%08llx, (branch) \n", data, this->cpu.pc);
            return;
        }

        // 处理系统调用
        if (this->cpu.exit_reason == CPU::ecall)
        {
            
            this->cpu.pc = this->cpu.reenter_pc;
            printf("inst = 0x%08x, pc = 0x%08llx, (syscall) \n", data, this->cpu.pc);
            // 获取系统调用编号：存储在通用寄存器 a7 里
            u64 syscall = this->cpu.cpu_get_gp_reg(a7);
            // 执行系统调用
            u64 ret = do_syscall(this->cpu, syscall);
            // 保存系统调用返回值：返回到通用寄存器 a0 里
            this->cpu.cpu_set_gp_reg(a0, ret);
            return;
        }
        

        printf("inst = 0x%08x, pc = 0x%08llx,\n", data, this->cpu.pc);

        this->cpu.regs[CPU::zero] = 0;  // zero寄存器清零             
        this->cpu.pc += insn.rvc ? 2 : 4;  // 如果为压缩指令步进2，否则步进4
    }




};





#endif // MULATOR_MACHINE_HPP