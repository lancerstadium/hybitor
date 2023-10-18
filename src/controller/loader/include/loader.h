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

// ============================================================================ //
// loader API 定义 --> 实现 src/controller/loader/loader.c
// ============================================================================ //

/// @brief 加载镜像文件
static long load_img() {
    if (img_file == NULL) {
        Logy("Load img_file: %s. Use the default build-in image.", img_file);
        return 4096; // built-in image size
    }

    FILE *fp = fopen(img_file, "rb");
    Assertf(fp, "Can not open '%s'", img_file);

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);

    Logg("Load image is %s, size = %ld", img_file, size);

    fseek(fp, 0, SEEK_SET);
    int ret = fread(guest_to_host(RESET_VECTOR), size, 1, fp);
    assert(ret == 1);

    fclose(fp);
    return size;
}


#endif // _HYBITOR_CONTROLLER_LOADER_INCLUDE_LOADER_H_