/**
 * @brief 指令集启动头文件
 * @file src/isa/riscv64/init.h
 * @author lancerstadium
 * @date 2023-10-28
*/

#include "isa.h"
#include "memory/mmu.h"

// ============================================================================ //
// init 静态变量 && 函数
// ============================================================================ //


static const uint32_t isa_img [] = {
  0x3c048000,  // lui a0, 0x8000
  0xac800000,  // sw  zero, 0(a0)
  0x8c820000,  // lw  v0,0(a0)
  0x7000003f,  // sdbbp (used as hybitor_trap)
};


/// @brief 重新启动 cpu
static void restart_cpu() {
    cpu.pc = RESET_VECTOR;  // 初始化程序计数器
    cpu.gpr[0] = 0;         // 令零寄存器为0
}


// ============================================================================ //
// init API 实现 --> 声明 include/isa.h
// ============================================================================ //

void init_isa() {
    memcpy(guest_to_host(RESET_VECTOR), isa_img, sizeof(isa_img));  // 加载 build-in 镜像
    restart_cpu();  // 初始化虚拟机系统
    Logg("Init isa, cpu pc: " FMT_PADDR , (unsigned int)cpu.pc);
}
