/*
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-11 21:41:42
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-12 11:54:50
 * @FilePath: /hybitor_effect/subitem/hyload/elfload-test.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */

#define HYLOAD_INTERNAL 1
#include "hyload.h"
#include <stdio.h>


// read a elf file and mmap its' segments to virtual address
int main(int argc, char **argv) {

    if(argc != 2){
        printf("Usage: %s elf_file\n", argv[0]);
        return -1;
    }
    // load a elf file
    dump_elf_file(argv[1]);

    return 0;
}
