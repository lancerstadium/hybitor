/**
 * @brief hybitor loader 加载器器定义
 * @file src/controller/loader/loader.c
 * @author lancerstadium
 * @date 2023-10-18
*/

#include "common.h"
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>

static int get_section(Elf *elf, int i, GElf_Ehdr *ehdr,char **shname,GElf_Shdr *shdr, Elf_Data **data) {
    Elf_Scn *scn;
    scn = elf_getscn(elf, i);  //从elf描述符获取按照节索引获取节接口
	if (!scn)
    return 1;
    if (gelf_getshdr(scn, shdr) != shdr) // 通过节结构复制节表头
	return 2;
    *shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name); // 从指定的字符串表中通过偏移获取字符串
    if (!*shname || !shdr->sh_size)
		return 3;
    *data = elf_getdata(scn, 0);  //从节中获取节数据（经过了字节序的转换）
    if (!*data || elf_getdata(scn, *data) != NULL)
	    return 4;
    return 0;
}

#define EM_NONE         0       // No machine
#define EM_ARM          40      // ARM
#define EM_X86_64       62      // AMD x86-64 architecture
#define EM_AARCH64      183     // ARM AArch64
#define EM_RISCV        243     // RISC-V
#define EM_LOONGARCH    258     // LoongArch

static char* get_arch(GElf_Ehdr *ehdr) {
    switch (ehdr->e_machine)
    {
    case EM_NONE: return "none";
    case EM_386: return "i386";
    case EM_X86_64: return "x86_64";
    case EM_AARCH64: return "aarch64";
    case EM_ARM: return "arm";
    case EM_RISCV: return "riscv";
    default: return "unknown";
    }
}

static char* get_type(GElf_Ehdr *ehdr) {
    switch (ehdr->e_type) {
    case ET_NONE: return "none";
    case ET_REL: return "rel";
    case ET_EXEC: return "exec";
    case ET_DYN: return "dyn";
    case ET_CORE: return "core";
    default: return "unknown";
    }
}

static char* get_class(GElf_Ehdr *ehdr) {
    switch (ehdr->e_ident[EI_CLASS])
    {
    case ELFCLASSNONE: return "none";
    case ELFCLASS32: return "32-bit";
    case ELFCLASS64: return "64-bit";
    default: return "unknown";
    }
}

static void print_elf_info(GElf_Ehdr *ehdr) {
    printf("ELF Header:\n");
    printf("  Version: %d\n", ehdr->e_version);
    printf("  Type:    %s\n", get_type(ehdr));
    printf("  Entry:   %p\n", ehdr->e_entry);
    printf("  Class:   %s\n", get_class(ehdr));
    printf("  Machine: %s\n", get_arch(ehdr));
}


    


// ============================================================================ //
// loader API 实现 --> 定义 src/controller/loader/loader.h
// ============================================================================ //



long parse_file(char *file_path) {
    Elf *elf;
    int fd;
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    char *shname, *shname_prog;
    Elf_Data *data;
    if (elf_version(EV_CURRENT) == EV_NONE)
        return 0;
    fd = open(file_path, O_RDONLY, 0); // 打开elf文件
    Assertf(fd >= 0, "Can not open '%s'", file_path);
    elf = elf_begin(fd, ELF_C_READ, NULL); // 获取elf描述符,使用‘读取’的方式
    Assert(elf, "Can not get elf desc");
    Assert(gelf_getehdr(elf, &ehdr) == &ehdr, "Can not get elf ehdr");
    print_elf_info(&ehdr);
    
    for (int i = 1; i < ehdr.e_shnum; i++) {
        if (get_section(elf, i, &ehdr, &shname, &shdr, &data))
            continue;
        printf("section %-3d:%-18s data %-12p size %-6zd link %-3d flags %-2d type %-d\n", i, shname, data->d_buf, data->d_size, shdr.sh_link, (int)shdr.sh_flags, (int)shdr.sh_type);
        // if (strcmp(shname, ".text") == 0) {
        //     printf(".text data:\n");
        //     unsigned char *p = data->d_buf;
        //     for (int j = 0; j < data->d_size; j++) {
        //         if (j % 8 == 0) {
        //             printf("\n");
        //         }
        //         printf("%4x", *p++);
        //     }
        //     printf("\n");
        // }
    }
    return (long)data->d_size;
}

// load and parse a ELF file, print ehdr infomation
