/*
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-11 15:10:25
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-11 15:17:46
 * @FilePath: /hybitor_effect/subitem/hyarmdec/example.cpp
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <cstdint>
#include <iostream>

#include "hyarmdec.h"

int main() {
	uint32_t in = 0xd10083ff;   // sub sp, sp, #32
	hyarmdec::Inst out;
	arm64_decode(&in, 1, &out);
    print_inst(out);
	return 0;
}