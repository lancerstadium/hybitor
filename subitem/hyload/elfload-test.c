/*
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-11 21:41:42
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-11 22:03:18
 * @FilePath: /hybitor_effect/subitem/hyload/elfload-test.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */

#define HYLOAD_INTERNAL 1
#include "elf-def.h"
#include <stdio.h>


// read a elf file and mmap its' segments to virtual address
int main(int argc, char **argv) {

    // load a elf file
    if (argc != 2) {
        printf("usage: %s elf_file\n", argv[0]);
        return -1;
    }
    elf64_ehdr_t ehdr;
    if(load_elf_file(argv[1], &ehdr) == -1){
        return -1;
    }
    // print elf info
    print_ehdr_info(&ehdr);
    print_phdr_info(&ehdr);
    print_sections_info(&ehdr);
    print_segments_info(&ehdr);

    // mmap segments
    int fd = open(argv[1], O_RDONLY);
    u64 vaddr = mmap_segment_to_vaddr(fd, ehdr.e_entry);

    close(fd);

    return 0;
}
