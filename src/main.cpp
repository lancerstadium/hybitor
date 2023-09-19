/// \file main.cpp
/// \brief 接收并解析命令行参数，加载合适的 libtinycode-*.so



// 标准库
#include <iostream>


// 本地库
#include "cliparser/cliparser.hpp"
#include "capstone/capstone.h"


// 引用
using std::cout;
using std::string;
using std::endl;

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"


// 主程序入口
int main(int argc, char **argv)
{
    // --- 解析执行输入参数 ---
    // cliparser cp;                      
    // cp.cli_init();              // 初始化 CLI 环境
    // cp.cli_parse(argc, argv);   // 解析参数
    // cp.cli_exec();              // CLI 执行命令

    csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, (uint8_t*)CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

	return 0;
}