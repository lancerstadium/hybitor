/*
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-11 22:05:55
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-11 22:12:52
 * @FilePath: /hybitor_effect/subitem/hyload/example.cpp
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */



#include <iostream>

#include "hyload.h"

int main() {
    // load ./test/hello.x86_64
    dump_elf_file("./test/hello.x86_64");
    return 0;
}