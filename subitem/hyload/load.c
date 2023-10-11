/*
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-11 20:43:04
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-11 22:00:10
 * @FilePath: /hybitor_effect/subitem/hyload/load.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/mman.h>
#define HYLOAD_INTERNAL 1
#include "elf-def.h"


bool is_elf(elf64_ehdr_t *ehdr) {
    return memcmp(ehdr->e_ident, ELFMAG, 4) == 0;
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

void print_ehdr_info(elf64_ehdr_t *ehdr){
    printf("ELF Header:\n");
    printf("  Magic: %s\n", ehdr->e_ident);
    printf("  Class: %d\n", ehdr->e_ident[EI_CLASS]);
    printf("  Data: %d\n", ehdr->e_ident[EI_DATA]);
    printf("  Version: %d\n", ehdr->e_ident[EI_VERSION]);
    printf("  OS/ABI: %d\n", ehdr->e_ident[EI_OSABI]);
    printf("  ABI Version: %d\n", ehdr->e_ident[EI_ABIVERSION]);
    printf("  Type: %d\n", ehdr->e_type);
    printf("  Machine: %s\n", get_architecture_name(ehdr));
    printf("  Version: %d\n", ehdr->e_version);
    printf("  Entry: %lu\n", ehdr->e_entry);
    printf("  Program Header Offset: %lu\n", ehdr->e_phoff);
    printf("  Section Header Offset: %lu\n", ehdr->e_shoff);
    printf("  Flags: %lu\n", ehdr->e_flags);
    printf("  Header Size: %d\n", ehdr->e_ehsize);
    printf("  Program Header Entry Size: %d\n", ehdr->e_phentsize);
    printf("  Program Header Entry Count: %d\n", ehdr->e_phnum);
    printf("  Section Header Entry Size: %d\n", ehdr->e_shentsize);
    printf("  Section Header Entry Count: %d\n", ehdr->e_shnum);
    printf("  Section Header String Table Index: %d\n", ehdr->e_shstrndx);
    
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


void print_segments_info(elf64_ehdr_t *ehdr) {
    printf("Segments:\n");
    for (int i = 0; i < ehdr->e_phnum; i++)
    {
        elf64_phdr_t *phdr = (elf64_phdr_t *)(ehdr->e_phoff + ehdr->e_phentsize * i);
        printf("  Type: %d\n", phdr->p_type);
        printf("  Offset: %lu\n", phdr->p_offset);
        printf("  VirtAddr: %lu\n", phdr->p_vaddr);
        printf("  PhysAddr: %lu\n", phdr->p_paddr);
        printf("  FileSiz: %lu\n", phdr->p_filesz);
        printf("  MemSiz: %lu\n", phdr->p_memsz);
        printf("  Flags: %lu\n", phdr->p_flags);
        printf("  Align: %lu\n", phdr->p_align);
        printf("\n");
    }
}


int load_elf_file(char *filename, elf64_ehdr_t *ehdr)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open file error");
        return -1;
    }
    ehdr = (elf64_ehdr_t *)mmap(NULL, sizeof(elf64_ehdr_t), PROT_READ, MAP_PRIVATE, fd, 0);
    if (ehdr == MAP_FAILED)
    {
        perror("mmap file error");
        return -1;
    }
    printf("Successfully load elf file %s\n", filename);
    printf("ehdr addr: %p\n", ehdr);
    close(fd);
    return 0;
}

void dump_elf_file(char *filename)
{
    elf64_ehdr_t *ehdr;
    load_elf_file(filename, ehdr);
    print_ehdr_info(ehdr);
    print_sections_info(ehdr);
    print_segments_info(ehdr);
    munmap(ehdr, sizeof(elf64_ehdr_t));
}

u64 mmap_segment_to_vaddr(int fd, u64 vaddr) {
    // step1: load phdr to virtual address
    elf64_phdr_t *phdr = (elf64_phdr_t *)mmap(NULL, sizeof(elf64_phdr_t), PROT_READ, MAP_PRIVATE, fd, 0);
    if (phdr == MAP_FAILED) {
        perror("mmap file error");
        return -1;
    }
    

    // step2: mmap segment to vitual address
    u64 vaddr_tmp = vaddr;
    for (int i = 0; i < phdr->p_memsz / phdr->p_filesz; i++) {
        // align
        vaddr_tmp = (vaddr_tmp + phdr->p_align - 1) & ~(phdr->p_align - 1);
        // .data
        if (phdr->p_type == PT_LOAD){
            memcpy((void *)vaddr_tmp, (void *)(phdr->p_vaddr + i * phdr->p_filesz), phdr->p_filesz);
        }
        vaddr_tmp += phdr->p_filesz;
    }

    printf("mmap segment to vaddr: %lx\n, alloc size: %d", vaddr, vaddr_tmp - vaddr);

    // step3: print binary segment data, and decord it
    for (int i = 0; i < phdr->p_memsz / phdr->p_filesz; i++) {
        // print
        printf("0x%lx: ", vaddr + i * phdr->p_filesz);
        for (int j = 0; j < phdr->p_filesz; j++) {
            printf("%02x ", phdr->p_vaddr + i * phdr->p_filesz + j);
        }
        printf("\n");
    }

    // step4: free phdr
    munmap(phdr, sizeof(elf64_phdr_t));
    return vaddr;

}

