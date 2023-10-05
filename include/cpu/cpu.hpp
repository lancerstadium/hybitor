/**
 * \file include/cpu/cpu.h
 * \brief 模拟cpu
 */


#ifndef CPU_CPU_H
#define CPU_CPU_H


#include "memory/memory.hpp"
#include "core/interpreter.hpp"


// ============================================================================== //
// 虚拟机 vitrue machine
// ============================================================================== //


class VM
{
private:
    
public:

    state_t state;
    MMU mmu;
    Cache cache;

    VM() {}
    ~VM() {}

    /// @brief 获取通用寄存器的值
    /// @param reg 寄存器编号
    /// @return 存储值
    inline u64 get_gp_reg(i32 reg) {
        assert(reg >= 0 && reg <= num_gp_regs);
        return this->state.gp_regs[reg];
    }

    /// @brief 设置通用寄存器的值
    /// @param reg 寄存器编号
    /// @param data 设置值
    inline void set_gp_reg(i32 reg, u64 data) {
        assert(reg >= 0 && reg <= num_gp_regs);
        this->state.gp_regs[reg] = data;
    }

    void VM_setup(int argc, char *argv[])
    {
        size_t stack_size = 32 * 1024 * 1024; // 32MB 栈
        u64 stack = this->mmu.MMU_alloc(stack_size);
        this->state.gp_regs[sp] = stack + stack_size; // 栈指针寄存器
        this->state.gp_regs[sp] -= 8;                 // auxv
        this->state.gp_regs[sp] -= 8;                 // envp
        this->state.gp_regs[sp] -= 8;                 // argv end
        u64 args = argc - 1;
        for (int i = args; i > 0; i--)
        {
            size_t len = strlen(argv[i]);
            u64 addr = this->mmu.MMU_alloc(len + 1);
            MMU::mmu_write(addr, (u8 *)argv[i], len); // 将参数数据存到heap上
            this->state.gp_regs[sp] -= 8;           // argv[i]
            // 将 addr 地址值存入寄存器指向的地址（取地址的地址）
            MMU::mmu_write(this->state.gp_regs[sp], (u8 *)&addr, sizeof(u64));
        }
        this->state.gp_regs[sp] -= 8; // argc
        MMU::mmu_write(this->state.gp_regs[sp], (u8 *)&argc, sizeof(u64));
    }


    /// @brief 虚拟机加载可执行文件
    /// @param ld 文件加载器
    void VM_load_program(loader &ld)
    {
        // 如果是 ELF 文件
        this->mmu.MMU_load_elf(ld.parse_elf_file(), ld.input_file_name);
        // 设置程序计数器入口地址
        this->state.pc = this->mmu.entry;
    }

    /// @brief 解释执行
    void exec_block_interp()
    {
        static insn_t insn = {0};
        while (true)
        { // 内存循环
            u32 data = *(u32 *)TO_HOST(this->state.pc);
            insn_decode(&insn, data);       // 指令解码
            cout << "decode insn type: " << insn.type << endl;
            funcs[insn.type](&this->state, &insn); // 匹配执行
            // zero寄存器清零
            this->state.gp_regs[zero] = 0;
            // 如果指令继续执行，则跳出循环
            if (insn.cont)
                break;
            // 如果为压缩指令步进2，否则步进4
            this->state.pc += insn.rvc ? 2 : 4;
        }
    }

    /// @brief 虚拟机执行程序
    /// @return 跳出循环的原因
    enum exit_reason_t VM_exec_program()
    {
        while (true) // 虚拟机内层循环
        {
            // 设置跳出内循环原因为 none
            this->state.exit_reason = none;
            // 执行代码块
            exec_block_interp();
            // 确保跳出原因非 none
            assert(this->state.exit_reason != none);

            // 处理跳转事件：就是这里很快
            if (this->state.exit_reason == indirect_branch ||
                this->state.exit_reason == direct_branch)
            {
                // 设置PC值：从这里继续执行
                this->state.pc = this->state.reenter_pc;
                continue;
            }

            break;
        }
        // 更新 pc 值
        this->state.pc = this->state.reenter_pc;
        assert(this->state.exit_reason == ecall);
        return ecall;
    }

    
};



#endif // CPU_CPU_H