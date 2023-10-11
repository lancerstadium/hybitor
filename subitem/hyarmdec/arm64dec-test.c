/*
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-11 11:42:07
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-11 15:20:43
 * @FilePath: /hybitor_effect/subitem/hyarmdec/test.c
 * @Description: 测试 ARM64 指令解码器
 */

#include <stdio.h>
#include <stdlib.h>

#define HYARMDEC_INTERNAL

#include "hyarmdec.h"



// main：将指令读取为十六进制数字列表，解码，打印结果。
int main(int argc, char **argv)
{
    // Single instruction as argument?
    if (argc == 2)
    {
        u32 binst;
        Inst inst;
        sscanf(argv[1], "%x", &binst);
        arm64_decode(&binst, 1, &inst);
        print_inst(inst);
        return 0;
    }

    printf("Input your binst such as: ./build/arm64dec-test 0xd10083ff\n");

    return 0;
}
