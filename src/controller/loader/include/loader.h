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


// ============================================================================ //
// loader 变量声明 --> 定义 src/monitor/monitor.c
// ============================================================================ //

extern char *img_file;
extern char* default_img_file;

// ============================================================================ //
// loader API 定义 --> 实现 src/controller/loader/loader.c
// ============================================================================ //


/// @brief 加载镜像文件
static void set_load_img() {
    if (img_file == NULL) {
        Logy("Img_file: %s, Use default img: `%s`", img_file, default_img_file);
        img_file = default_img_file;
    } else {
        Logg("Set img_file: `%s`", img_file);
    }


    // FILE *fp = fopen(img_file, "rb");
    // Assertf(fp, "Can not open '%s'", img_file);

    // fseek(fp, 0, SEEK_END);
    // long size = ftell(fp);

    // Logg("Load image is %s, size = %ld", img_file, size);

    // fseek(fp, 0, SEEK_SET);
    // int ret = fread(guest_to_host(RESET_VECTOR), size, 1, fp);
    // assert(ret == 1);

    // fclose(fp);
}

/// @brief 修改加载镜像
/// @param file_path 新镜像位置
static void change_load_img(char *file_path) {
    FILE *fp = fopen(file_path, "rb");
    if(!fp) {
        Logy("Can not open file: %s", file_path);
        return;
    }
    fclose(fp);
    img_file = file_path;
    Logg("Change img_file to: `%s`", img_file);
}

/// @brief 解析 ELF 文件
/// @param file_path 文件路径
/// @return 数据长度
long parse_file(char *file_path);


#endif // _HYBITOR_CONTROLLER_LOADER_INCLUDE_LOADER_H_