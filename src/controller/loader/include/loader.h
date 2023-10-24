/**
 * @brief hybitor loader 加载器器定义
 * @file src/controller/loader/include/loader.h
 * @author lancerstadium
 * @date 2023-10-18
*/

#ifndef _HYBITOR_CONTROLLER_LOADER_INCLUDE_LOADER_H_
#define _HYBITOR_CONTROLLER_LOADER_INCLUDE_LOADER_H_

#include "common.h"
#include "memory/mmu.h"
#include <libelf.h>
#include <gelf.h>


// ============================================================================ //
// loader 变量声明 --> 定义 src/monitor/monitor.c
// ============================================================================ //

extern char *img_file;
extern char* default_img_file;

typedef struct ELF_IMG {
    void *addr;                 // 映射地址
    GElf_Ehdr ehdr;             // ELF头
    GElf_Shdr *shdr;            // 段表
    GElf_Off shstrtab_offset;   // 
    off_t size;                 // 文件大小
} ELF_IMG;

extern ELF_IMG elf_img;     // ELF文件镜像声明 --> 定义 loader.h

// ============================================================================ //
// loader API 定义 --> 实现 src/controller/loader/loader.c
// ============================================================================ //

/// @brief 加载 ELF 文件
/// @param file_path 文件路径
/// @return 数据长度
long load_img_file(char *file_path);


/// @brief 释放 ELF 文件
/// @param file_path 文件路径
/// @return 数据长度
long free_img_file(char *file_path);

/// @brief 显示 ELF 文件头信息
void display_img_header_info();

/// @brief 显示 ELF 段表信息
void display_img_section_info();

/// @brief 显示 ELF 符号表信息
void display_img_symbol_info();

/// @brief 显示 ELF 程序头信息
void display_img_program_info();

/// @brief 加载镜像文件
void set_load_img();

/// @brief 修改加载镜像
/// @param file_path 新镜像位置
bool change_load_img(char *file_path);




#endif // _HYBITOR_CONTROLLER_LOADER_INCLUDE_LOADER_H_