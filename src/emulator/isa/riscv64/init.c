/**
 * @brief 指令集启动头文件
 * @file src/isa/riscv64/init.h
 * @author lancerstadium
 * @date 2023-10-28
*/

#include "emulator/isa.h"
#include "emulator/softmmu/softmmu.h"

// ============================================================================ //
// init 静态变量 && 函数
// ============================================================================ //


static const uint32_t isa_img [] = {
  0x00000297,  // auipc t0,0
  0x00028823,  // sb  zero,16(t0)
  0x0102c503,  // lbu a0,16(t0)
  0x00100073,  // ebreak (used as hybitor_trap)
  0xdeadbeef,  // some data
};


/// @brief 重新启动 cpu
static void restart_cpu() {
    cpu.pc = RESET_VECTOR;  // 初始化程序计数器
    cpu.gpr[0] = 0;         // 令零寄存器为0
}


// ============================================================================ //
// init API 实现 --> 声明 include/emulator/isa.h
// ============================================================================ //

void init_isa() {
    memcpy(guest_to_host(RESET_VECTOR), isa_img, sizeof(isa_img));  // 加载 build-in 镜像
    restart_cpu();  // 初始化虚拟机系统
    Logb("Init isa, cpu pc: " FMT_PADDR , (unsigned int)cpu.pc);
}
