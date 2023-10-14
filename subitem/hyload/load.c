/*
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-11 20:43:04
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-12 18:22:00
 * @FilePath: /hybitor_effect/subitem/hyload/load.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */


#include <string.h>
#include <stddef.h>
#include <sys/mman.h>
#include "hyload.h"


// 检查文件魔数
bool is_elf(elf64_ehdr_t *ehdr) {
    return *(u32 *)ehdr == *(u32 *)ELFMAG;
}


bool is_32bit(elf64_ehdr_t *ehdr) {
    return ehdr->e_ident[EI_CLASS] == ELFCLASS32;
}

bool is_64bit(elf64_ehdr_t *ehdr) {
    return ehdr->e_ident[EI_CLASS] == ELFCLASS64;
}

char* get_architecture_name(elf64_ehdr_t *ehdr){
    switch (ehdr->e_machine)
    {
    case EM_X86_64:
        return "x86_64";
    case EM_AARCH64:
        return "aarch64";
    case EM_ARM:
        return "arm";
    case EM_RISCV:
        return "riscv";
    case EM_LOONGARCH:
        return "loongarch";
    default:
        return "unknown";
    }
}

char* get_elf_class(elf64_ehdr_t *ehdr){
    switch (ehdr->e_ident[EI_CLASS])
    {
    case ELFCLASSNONE:
        return "none";
    case ELFCLASS32:
        return "32-bit";
    case ELFCLASS64:
        return "64-bit";
    default:
        return "unknown";
    }
}


char* get_elf_type(elf64_ehdr_t *ehdr){
    switch (ehdr->e_type)
    {
    case ET_NONE:
        return "none";
    case ET_REL:
        return "rel";
    case ET_EXEC:
        return "exec";
    case ET_DYN:
        return "dyn";
    case ET_CORE:
        return "core";
    default:
        return "unknown";
    }
}

void print_ehdr_info(elf64_ehdr_t *ehdr){
    printf("ELF Header:\n");
    printf("  Class: %s\n", get_elf_class(ehdr));
    printf("  Data: %d\n", ehdr->e_ident[EI_DATA]);
    printf("  Version: %d\n", ehdr->e_ident[EI_VERSION]);
    printf("  OS/ABI: %d\n", ehdr->e_ident[EI_OSABI]);
    printf("  ABI Version: %d\n", ehdr->e_ident[EI_ABIVERSION]);
    printf("  Type: %s\n", get_elf_type(ehdr));
    printf("  Machine: %s\n", get_architecture_name(ehdr));
    printf("  Version: %d\n", ehdr->e_version);
    printf("  Entry: %lu\n", ehdr->e_entry);
    printf("  Program Header Offset: %lu\n", ehdr->e_phoff);
    printf("  Section Header Offset: %lu\n", ehdr->e_shoff);
    printf("  Flags: %lu\n", ehdr->e_flags);
    printf("  Header size: %lu\n", ehdr->e_ehsize);
    printf("  Program Header size: %lu\n", ehdr->e_phentsize);
    printf("  Program Header count: %lu\n", ehdr->e_phnum);
    printf("  Section Header size: %lu\n", ehdr->e_shentsize);
    printf("  Section Header count: %lu\n", ehdr->e_shnum);
    printf("  Section Header string table index: %lu\n", ehdr->e_shstrndx);

}

void print_phdr_info(elf64_phdr_t *phdr){
    printf("Program Header:\n");
    printf("  Type: %d\n", phdr->p_type);
    printf("  Offset: %lu\n", phdr->p_offset);
    printf("  VirtAddr: %lu\n", phdr->p_vaddr);
    printf("  PhysAddr: %lu\n", phdr->p_paddr);
    printf("  FileSiz: %lu\n", phdr->p_filesz);
    printf("  MemSiz: %lu\n", phdr->p_memsz);
    printf("  Flags: %lu\n", phdr->p_flags);
    printf("  Align: %lu\n", phdr->p_align);
}

void print_sections_info(elf64_ehdr_t *ehdr){
    printf("Sections:\n");
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        elf64_shdr_t *shdr = (elf64_shdr_t *)(ehdr->e_shoff + ehdr->e_shentsize * i);
        printf("  Name: %s\n", shdr->sh_name);
        printf("  Type: %d\n", shdr->sh_type);
        printf("  Flags: %d\n", shdr->sh_flags);
        printf("  Addr: %lu\n", shdr->sh_addr);
        printf("  Offset: %lu\n", shdr->sh_offset);
        printf("  Size: %lu\n", shdr->sh_size);
        printf("  Link: %d\n", shdr->sh_link);
        printf("  Info: %d\n", shdr->sh_info);
        printf("  Align: %lu\n", shdr->sh_addralign);
        printf("  EntSize: %lu\n", shdr->sh_entsize);
        printf("\n");
    }
}

print_segment_data(elf64_phdr_t *phdr, FILE *file)
{
    printf("Segment Data:\n");
    // print binary data from segment
    fseek(file, phdr->p_offset, SEEK_SET);
    
    for (int i = 0; i < phdr->p_filesz; i++)
    {
        // print segment info and data in hex
        printf("%02x", phdr->p_vaddr + i);
        printf(" ");
        printf("%02x", phdr->p_memsz - i);
        printf("\n");
    }
}

void load_phdr(elf64_phdr_t *phdr, elf64_ehdr_t *ehdr, i64 i, FILE *file) {
    // 找到第 i 个 program header 偏移量
    if(fseek(file, ehdr->e_phoff + ehdr->e_phentsize * i, SEEK_SET) != 0) {
        perror("seek file failed");
    }
    // 加载到指针 phdr 中
    if(fread((void *)phdr, 1, sizeof(elf64_phdr_t), file) != sizeof(elf64_phdr_t)) {
        perror("file too small");
    }
}



void print_segments_info(elf64_ehdr_t *ehdr, FILE *file) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
        elf64_phdr_t *phdr = (elf64_phdr_t *)(ehdr->e_phoff + ehdr->e_phentsize * i);
        load_phdr(phdr, ehdr, i, file);
        print_phdr_info(phdr);
        print_segment_data(phdr, file);
        printf("\n");
    }
}


/// @brief 匹配 segment 类型
/// @param flags 类型符号
/// @return segment 类型
static int flags_to_mmap_prot(u32 flags) {
    return (flags & PF_R ? PROT_READ : 0) |
           (flags & PF_W ? PROT_WRITE: 0) |
           (flags & PF_X ? PROT_EXEC: 0);
}

/// @brief 加载 program header 的 segment 到内存
/// @param mmu 内存对象
/// @param phdr program header 对象
/// @param fd 文件标识符
// static void load_segment(elf64_phdr_t *phdr, int fd) {
//     int page_size = getpagesize();          // 获取页面大小
//     u64 offset = phdr->p_offset;            // 获取偏移量
//     u64 vaddr = TO_HOST(phdr->p_vaddr);     // 主机虚拟地址
//     u64 aligned_vaddr = ROUNDDOWN(vaddr, page_size);
//     u64 filesz = phdr->p_filesz + (vaddr - aligned_vaddr);
//     u64 memsz = phdr->p_memsz + (vaddr - aligned_vaddr);
    
//     // mmap page aligned: 对齐 page size
//     int prot = flags_to_mmap_prot(phdr->p_flags);
//     u64 addr = (u64)mmap((void *)aligned_vaddr, filesz, prot, MAP_PRIVATE | MAP_FIXED, 
//                         fd, ROUNDDOWN(offset, page_size));
//     assert(addr == aligned_vaddr);
//     // .bss section
//     u64 remaining_bss = ROUNDUP(memsz, page_size) - ROUNDUP(filesz, page_size);
//     if (remaining_bss > 0) {
//         u64 addr = (u64)mmap((void *)(aligned_vaddr + ROUNDUP(filesz, page_size)),
//              remaining_bss, prot, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
//         assert(addr == aligned_vaddr + ROUNDUP(filesz, page_size));
//     }

//     mmu->host_alloc = MAX(mmu->host_alloc, (aligned_vaddr + ROUNDUP(memsz, page_size)));
//     mmu->base = mmu->alloc = TO_GUEST(mmu->host_alloc);
// }


int load_elf_file(int fd, elf64_ehdr_t *ehdr)
{
    u8 buf[sizeof(elf64_ehdr_t)];
    FILE *file = fdopen(fd, "rb");  // 二进制只读
    if(fread(buf, 1, sizeof(elf64_ehdr_t), file) != sizeof(elf64_ehdr_t)) 
    {
        perror("open file's ehdr error");
        return -1;
    }
    ehdr = (elf64_ehdr_t*)buf;    // 强转类型
    if(!is_elf(ehdr)){
        perror("file is not elf");
        return -1;
    }

    printf("File Class: %s", get_elf_class(ehdr));
    
    printf("Architecture: %s\n", get_architecture_name(ehdr));
    
    print_ehdr_info(ehdr);
    // print_sections_info(ehdr);
    // print_segments_info(ehdr, file);
    /// TODO: load phdr

    return 0;
}

void dump_elf_file(char *filename)
{
    int fd = open(filename, O_RDONLY);
    if(fd == -1){
        perror("open file error");
        return;
    }
    elf64_ehdr_t ehdr;
    if(load_elf_file(fd, &ehdr) == -1){
        return;
    }
    // print_ehdr_info(&ehdr);
    // print_sections_info(&ehdr);
    // print_segments_info(ehdr);
    close(fd);
}

