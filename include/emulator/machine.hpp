/// \file emulator/machine.hpp
/// \brief RISC-V64 machine 模拟

#ifndef EMULATOR_MACHINE_HPP
#define EMULATOR_MACHINE_HPP


#include "emulator/decoder.hpp"


class VM
{
private:

public:

    CPU cpu;
    u64 p_addr;         // 物理地址
    decoder dc;


    /// @brief 虚拟机初始化
    VM() {
        this->cpu.cpu_init();
        this->cpu.bus.dram.dram_init();
        this->dc.init_inst_func();
    }
    ~VM() {}

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
    void VM_cpu_exec_once()
    {
        this->cpu.regs[0] = 0;
        if (this->cpu.pc == p_addr) {
            this->cpu.state = CPU::CPU_STOP; // 放置于停止状态
            printf("breakpoint at 0x%lx\n", (unsigned long)p_addr);
            p_addr = -1;
            return;
        }
        u32 inst = this->cpu.cpu_fetch_inst();
        printf("inst = 0x%08x\n", inst);

        dc.set_decoder(inst);
        if (dc.inst_name == (int)INST_NAME::INST_NUM) {
            this->cpu.state = CPU::CPU_STOP;
            printf("* Hybitor REPL Stop, Error Info: \n");
            printf("* PC = 0x%08lx inst=0x%08x inst_name = %d\n", (unsigned long)this->cpu.pc, inst, dc.inst_name);
            todo("Unsupported instruction or EOF");
            return;
        }

        dc.dnpc = dc.snpc = this->cpu.pc + 4;
        dc.cpu = this->cpu;
        dc.exec_inst(this->cpu);
        this->cpu.pc = dc.dnpc;
    }


};





#endif // MULATOR_MACHINE_HPP