/**
 * @brief Hybitor 程序 的主函数
 * @file src/hybitor.c
 * @author lancerstadium
 * @date 2023-10-13
*/

#include "common.h"

int main(int argc, char *argv[]) {
    
    init_controller_main(argc, argv);
    start_controller_main();
    
    return 0;
}