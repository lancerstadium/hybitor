


#ifndef ELF_DEF_H
#define ELF_DEF_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>


/// ==== 类型定义 ==== ///
#ifdef HYLOAD_INTERNAL
typedef unsigned int uint;
typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;
typedef float    f32;
typedef double   f64;
#else
#define uint unsigned int
#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define i8 int8_t
#define i16 int16_t
#define i32 int32_t
#define i64 int64_t
#define f32 float
#define f64 double
#endif  // HYLOAD_INTERNAL


/// ==== 结构体接口 ==== ///
#ifndef __cplusplus // C版本
typedef struct elf64_ehdr_t elf64_ehdr_t;
typedef struct elf64_phdr_t elf64_phdr_t;
typedef struct elf64_shdr_t elf64_shdr_t;
typedef struct elf64_sym_t elf64_sym_t;
#else   // C++版本
namespace hyload {  // hyload 命名空间
#endif // __cplusplus


#define EI_NIDENT       16

/// e_ident
#define EI_MAG0         0       // File identification index.
#define EI_MAG1         1       // File identification index.
#define EI_MAG2         2       // File identification index.
#define EI_MAG3         3       // File identification index.
#define EI_CLASS        4       // e_ident 第四个字节 EI_CLASS 记录ELF文件类型
#define EI_DATA         5       // Data encoding.
#define EI_VERSION      6       // File version.
#define EI_OSABI        7       // OS/ABI identification.
#define EI_ABIVERSION   8       // ABI version.
#define ELFMAG          "\177ELF"   // ELF 魔数 -> 用于识别文件类型

/// ELF 体系结构标识符
#define EM_NONE         0       // No machine
#define EM_ARM          40      // ARM
#define EM_X86_64       62      // AMD x86-64 architecture
#define EM_AARCH64      183     // ARM AArch64
#define EM_RISCV        243     // RISC-V
#define EM_LOONGARCH    258     // LoongArch

/// 文件类型
#define ET_NONE         0       // No file type
#define ET_REL          1       // Relocatable file
#define ET_EXEC         2       // Executable file
#define ET_DYN          3       // Shared object file
#define ET_CORE         4       // Core file

/// e_ident 第四个字节 EI_CLASS 记录ELF文件类型
#define ELFCLASSNONE    0
#define ELFCLASS32      1
#define ELFCLASS64      2
#define ELFCLASSNUM     3

#define PT_LOAD         1

#define PF_X            0x1
#define PF_W            0x2
#define PF_R            0x4


#define R_X86_64_PC32   2



/// @brief ELF header 结构体
struct elf64_ehdr_t {
    u8 e_ident[EI_NIDENT];  // 文件标识符
    u16 e_type;             // 文件类型
    u16 e_machine;          // HOST体系架构
    u32 e_version;          // 文件版本
    u64 e_entry;            // 程序入口地址
    u64 e_phoff;            // program header偏移量
    u64 e_shoff;            // section header偏移量
    u32 e_flags;            // 文件标志
    u16 e_ehsize;           // 文件头大小
    u16 e_phentsize;        // program header大小
    u16 e_phnum;            // program header数量
    u16 e_shentsize;        // section header大小
    u16 e_shnum;            // section header数量
    u16 e_shstrndx;         // section header字符串表索引
} ;



/// @brief Program header 结构体
struct elf64_phdr_t {
    u32 p_type;             // 类型
    u32 p_flags;            // 标志
    u64 p_offset;           // 偏移量
    u64 p_vaddr;            // 虚拟内存地址
    u64 p_paddr;            // 物理内存地址
    u64 p_filesz;           // 文件大小
    u64 p_memsz;            // 内存大小
    u64 p_align;            // 对齐
};

/// @brief Section header 结构体
struct elf64_shdr_t {
    u32 sh_name;
    u32 sh_type;
    u32 sh_flags;
    u64 sh_addr;
    u64 sh_offset;
    u64 sh_size;
    u32 sh_link;
    u32 sh_info;
    u64 sh_addralign;
    u64 sh_entsize;
};

/// @brief 符号表
struct elf64_sym_t{
	u32 st_name;
	u8  st_info;
	u8  st_other;
	u16 st_shndx;
	u64 st_value;
	u64 st_size;
};


/// @brief 重定位表
struct elf64_rela_t{
    u64 r_offset;
    u32 r_type;
    u32 r_sym;
    i64 r_addend;
};




/// ==== 函数接口 ==== ///
#ifndef __cplusplus // C版本
    bool is_elf(elf64_ehdr_t *ehdr);
    bool is_32bit(elf64_ehdr_t *ehdr);
    bool is_64bit(elf64_ehdr_t *ehdr);
    char* get_architecture_name(elf64_ehdr_t *ehdr);
    void print_ehdr_info(elf64_ehdr_t *ehdr);
    void print_phdr_info(elf64_phdr_t *phdr);
    void print_sections_info(elf64_ehdr_t *ehdr);
    void print_segments_info(elf64_ehdr_t *ehdr, FILE *file);
    int load_elf_file(int fd, elf64_ehdr_t *ehdr);
    void dump_elf_file(char *filename);
#else // C++ 版本
}   // hyload 命名空间
extern "C" {
    bool is_elf(hyload::elf64_ehdr_t *ehdr);
    bool is_32bit(hyload::elf64_ehdr_t *ehdr);
    bool is_64bit(hyload::elf64_ehdr_t *ehdr);
    char* get_architecture_name(hyload::elf64_ehdr_t *ehdr);
    void print_ehdr_info(hyload::elf64_ehdr_t *ehdr);
    void print_phdr_info(hyload::elf64_phdr_t *phdr);
    void print_sections_info(hyload::elf64_ehdr_t *ehdr);
    void print_segments_info(hyload::elf64_ehdr_t *ehdr, FILE *file);
    int load_elf_file(int fd, hyload::elf64_ehdr_t *ehdr);
    void dump_elf_file(char *filename);
}
#endif // __cplusplus



/// ==== 类型定义取消：防止污染 ==== ///
#ifndef HYARMDEC_INTERNAL
#undef uint
#undef u8
#undef u16
#undef u32
#undef u64
#undef i8
#undef i16
#undef i32
#undef i64
#undef f32
#undef f64
#endif // HYARMDEC_INTERNAL


#endif // ELF_DEF_H

