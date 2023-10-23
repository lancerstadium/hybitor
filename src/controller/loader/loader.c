/**
 * @brief hybitor loader 加载器器定义
 * @file src/controller/loader/loader.c
 * @author lancerstadium
 * @date 2023-10-18
*/

#include "loader.h"
#include <fcntl.h>
#include <sys/mman.h>

// ============================================================================ //
// loader 宏定义 & 结构体
// ============================================================================ //

#define EM_NONE         0       // No machine
#define EM_ARM          40      // ARM
#define EM_X86_64       62      // AMD x86-64 architecture
#define EM_AARCH64      183     // ARM AArch64
#define EM_RISCV        243     // RISC-V
#define EM_LOONGARCH    258     // LoongArch

#define ELF_PRINT_FORMAT "  %-35s%s\n"

// 下面是一些奇奇怪怪的宏, 用于判断 program header 中最后的 Segment Sections

#define PT_GNU_MBIND_NUM 4096
#define PT_GNU_MBIND_LO (PT_LOOS + 0x474e555)
#define PT_GNU_MBIND_HI (PT_GNU_MBIND_LO + PT_GNU_MBIND_NUM - 1)
#define PT_GNU_SFRAME (PT_LOOS + 0x474e554) /* SFrame stack trace information */


ELF_IMG elf_img;

static int truncated = 0;   // 截断

// ============================================================================ //
// loader --> elf header
// ============================================================================ //

static inline int is_pie() {
    return 1;
}

static char* get_arch(GElf_Ehdr ehdr) {
    switch (ehdr.e_machine)
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

static char* get_type(GElf_Ehdr ehdr) {
    switch (ehdr.e_type) {
    case ET_NONE: return "NONE (None)";
    case ET_REL: return "REL (Relocatable file)";
    case ET_EXEC: return "EXEC (Executable file)";
    case ET_DYN: 
        if(is_pie()){
            return "DYN (Position-Independent Executable file)";
        } else {
            return "DYN (Shared object file)";
        }
    case ET_CORE: return "CORE (Core file)";
    default: return "unknown";
    }
}


static char* get_class(GElf_Ehdr ehdr) {
    switch (ehdr.e_ident[EI_CLASS])
    {
    case ELFCLASSNONE: return "none";
    case ELFCLASS32: return "32-bit";
    case ELFCLASS64: return "64-bit";
    default: return "unknown";
    }
}

static char* get_data_endian(GElf_Ehdr ehdr) {
    switch (ehdr.e_ident[EI_DATA])
    {
    case ELFDATANONE: return "none";
    case ELFDATA2LSB: return "2's complement, little endian";
    case ELFDATA2MSB: return "2's complement, big endian";
    default: return "unknown";
    }
}

static char* get_version(GElf_Ehdr ehdr) {
    switch (ehdr.e_ident[EI_VERSION])
    {
    case EV_NONE: return "none";
    case EV_CURRENT: return "current";
    default: return "unknown";
    }
}

static char* get_osabi(GElf_Ehdr ehdr) {
    switch (ehdr.e_ident[EI_OSABI])
    {
    case ELFOSABI_NONE: return "UNIX - System V";
    case ELFOSABI_HPUX: return "UNIX - HP-UX";
    case ELFOSABI_NETBSD: return "UNIX - NetBSD";
    case ELFOSABI_LINUX: return "UNIX - GNU/Linux";
    case ELFOSABI_SOLARIS: return "UNIX - Solaris";
    case ELFOSABI_AIX: return "UNIX - AIX";
    case ELFOSABI_IRIX: return "UNIX - IRIX";
    case ELFOSABI_FREEBSD: return "UNIX - FreeBSD";
    case ELFOSABI_TRU64: return "UNIX - TRU64 UNIX";
    case ELFOSABI_MODESTO: return "Novell - Modesto";
    case ELFOSABI_OPENBSD: return "UNIX - OpenBSD";
    case ELFOSABI_ARM: return "ARM architecture ABI";
    case ELFOSABI_STANDALONE: return "Stand-alone (embedded) ABI";
    default: return "unknown";
    }
}

static int get_section(Elf *elf, int i, GElf_Ehdr *ehdr,char **shname,GElf_Shdr *shdr, Elf_Data **data) {
    Elf_Scn *scn;
    scn = elf_getscn(elf, i);  //从elf描述符获取按照节索引获取节接口
	Assert(scn, "No section in elf");
    Assert(gelf_getshdr(scn, shdr) == shdr, "No shdr in section"); // 通过节结构复制节表头
    *shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name); // 从指定的字符串表中通过偏移获取字符串
    Assert(*shname && shdr->sh_size, "No size in section");
    *data = elf_getdata(scn, 0);  //从节中获取节数据（经过了字节序的转换）
    Assert(*data && elf_getdata(scn, *data) == NULL, "No data in section");
    return 0;
}

static void print_elf_header_info(GElf_Ehdr ehdr) {
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf("%2.2x ", ehdr.e_ident[i]);
    }
    printf("\n");
    printf(ELF_PRINT_FORMAT, "Class:", get_class(ehdr));
    printf(ELF_PRINT_FORMAT, "Data:", get_data_endian(ehdr));
    printf("  %-35s%d (%s)\n", "Version:", ehdr.e_version, get_version(ehdr));
    printf(ELF_PRINT_FORMAT, "OS/ABI:", get_osabi(ehdr));
    printf("  %-35s%u\n", "ABI version:", ehdr.e_ident[EI_ABIVERSION]);
    printf(ELF_PRINT_FORMAT, "Type:", get_type(ehdr));
    printf(ELF_PRINT_FORMAT, "Machine:", get_arch(ehdr));
    printf("  Version:                           0x%x\n", ehdr.e_version);
    printf("  Entry point address:               0x%llx\n", (unsigned long long)ehdr.e_entry);
    printf("  Start of program headers:          %lld (bytes into file)\n", (unsigned long long)ehdr.e_phoff);
    printf("  Start of section headers:          %lld (bytes into file)\n", (unsigned long long)ehdr.e_shoff);
    printf("  Flags:                             0x%x\n", ehdr.e_flags);
    printf("  Size of this header:               %d (bytes)\n", ehdr.e_ehsize);
    printf("  Size of program headers:           %d (bytes)\n", ehdr.e_phentsize);
    printf("  Number of program headers:         %d\n", ehdr.e_phnum);
    printf("  Size of section headers:           %d (bytes)\n", ehdr.e_shentsize);
    printf("  Number of section headers:         %d\n", ehdr.e_shnum);
    printf("  Section header string table index: %d\n", ehdr.e_shstrndx);
}



// ============================================================================ //
// loader -> section
// ============================================================================ //


char *get_section_type(Elf64_Word section_type) {
    switch (section_type) {
        case SHT_NULL:
            return "NULL";
        case SHT_PROGBITS:
            // 该部分保存由程序定义的信息,其格式和含义完全由程序决定.
            // 其格式和含义完全由程序决定
            return "PROGBITS";
        case SHT_SYMTAB:
            // 符号表
            return "SYMTAB";
        case SHT_STRTAB:
            // 字符串表
            return "STRTAB";
        case SHT_RELA:
            // 有明确后缀的重定位条目
            return "RELA";
        case SHT_HASH:
            // hash 表
            return "HASH";
        case SHT_DYNAMIC:
            // 动态链接
            return "DYNAMIC";
        case SHT_NOTE:
            // 包含以某种方式标记文件的信息
            // 比如 .note.gnu.propert
            return "NOTE";
        case SHT_NOBITS:
            // 文件中不占空间
            // bss
            return "NOBITS";
        case SHT_REL:
            // 没有明确后缀的重定位条目
            return "REL";
        case SHT_DYNSYM:
            // 符号表
            return "DYNSYM";
        case SHT_SHLIB:
            // 保留
            return "";
            // 这里其实有一大堆 GNU 的扩展符号
            // https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=binutils/readelf.c;h=b872876a8b660be19e1ffc66ee300d0bbfaed345;hb=HEAD#l4942
        case SHT_INIT_ARRAY:
            return "INIT_ARRAY";
        case SHT_FINI_ARRAY:
            return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY:
            return "PREINIT_ARRAY";
        case SHT_GROUP:
            return "GROUP";
        case SHT_SYMTAB_SHNDX:
            return "SYMTAB SECTION INDICES";
        case SHT_GNU_verdef:
            return "VERDEF";
        case SHT_GNU_verneed:
            return "VERNEED";
        case SHT_GNU_versym:
            return "VERSYM";
        case 0x6ffffff0:
            return "VERSYM";
        case 0x6ffffffc:
            return "VERDEF";
        case 0x7ffffffd:
            return "AUXILIARY";
        case 0x7fffffff:
            return "FILTER";
        default:
            return "";
    }
}

/**
 * @brief 获取段标记位信息
 *
 * @param section_flag
 * @return char*
 */
char *get_section_flag(Elf64_Xword section_flag) {
    // https://sourceware.org/git?p=binutils-gdb.git;a=blob;f=binutils/readelf.c;h=b872876a8b660be19e1ffc66ee300d0bbfaed345;hb=HEAD#l6812

    // SHF_WRITE:段内容可以被写入.
    // SHF_ALLOC:段在程序执行时被分配内存.
    // SHF_EXECINSTR:段包含可执行指令.
    // SHF_MASKPROC:该位由处理器架构定义.
    static char flags[20];
    char *p = flags;
    if (section_flag & SHF_WRITE)
        *p++ = 'W';
    if (section_flag & SHF_ALLOC)
        *p++ = 'A';
    if (section_flag & SHF_EXECINSTR)
        *p++ = 'X';
    if (section_flag & SHF_MERGE)
        *p++ = 'M';
    if (section_flag & SHF_STRINGS)
        *p++ = 'S';
    if (section_flag & SHF_INFO_LINK)
        *p++ = 'I';
    if (section_flag & SHF_LINK_ORDER)
        *p++ = 'L';
    if (section_flag & SHF_OS_NONCONFORMING)
        *p++ = 'O';
    if (section_flag & SHF_GROUP)
        *p++ = 'G';
    if (section_flag & SHF_TLS)
        *p++ = 'T';
    if (section_flag & SHF_EXCLUDE)
        *p++ = 'E';
    *p = 0;
    return flags;
}

/**
 * @brief readelf -S 读取并输出段表信息
 *
 * @param elf_img
 * @return int
 */
int print_elf_section_table(ELF_IMG *elf_img) {
    int section_number = elf_img->ehdr.e_shnum;
    printf("There are %d section headers, starting at offset 0x%lx:\n", section_number, elf_img->ehdr.e_shoff);

    printf("\nSection %s:\n", section_number == 1 ? "Header" : "Headers");

    printf("  [Nr] Name              Type             Address           Offset\n");
    printf("       Size              EntSize          Flags  Link  Info  Align\n");
    for (int i = 0; i < section_number; i++) {
        Elf64_Shdr *shdr = &elf_img->shdr[i];
        char number[3] = " x";
        if (i / 10) {
            number[0] = '0' + i / 10;
        }
        number[1] = '0' + i % 10;
        Assert(shdr, "shdr is null");
        char *section_type = get_section_type(shdr->sh_type);
        char *section_flag = get_section_flag(shdr->sh_flags);
        // 段名的获取方式是通过 shstrtab + sh_name(偏移地址) 得到的
        char *section_name = elf_strptr(elf_img->elf, elf_img->ehdr.e_shstrndx, shdr->sh_name); // 从指定的字符串表中通过偏移获取字符串
        Assert(section_name, "section_name is null");
        // 过长的字符串输出截断
        // readelf -S examples/SimpleSection.o
        if (!truncated && strlen(section_name) > 16) {
            char short_section_name[18];
            strncpy(short_section_name, section_name, 12);
            strncpy(short_section_name + 12, "[...]", 6);
            short_section_name[17] = 0;
            section_name = short_section_name;
        }
        printf(
            "  [%2s] %-17s %-16s %016lx  %08lx\n", number, section_name, section_type, shdr->sh_addr, shdr->sh_offset);
        printf("       %016lx  %016lx %3s%8d%6d     %ld\n",
               shdr->sh_size,  // 段的大小, 对于每一个段可以通过 sh_size 和 对应结构体大小计算表项数量
               shdr->sh_entsize,  // 段条目的大小
               section_flag,
               shdr->sh_link,  // 对于重定位表(.rela)和符号表(.symtab)
               shdr->sh_info,  // sh_link 和 sh_info 这两个字段有意义, 其他无意义
               shdr->sh_addralign);
    }

    printf("Key to Flags:\n");
    printf("  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n");
    printf("  L (link order), O (extra OS processing required), G (group), T (TLS),\n");
    printf("  C (compressed), x (unknown), o (OS specific), E (exclude),\n");
    printf("  D (mbind), l (large), p (processor specific)\n");
    return 0;
}


// ============================================================================ //
// loader symbol
// ============================================================================ //

char *get_symbol_type(int st_info) {
    switch (st_info) {
        case STT_NOTYPE:
            // 符号类型未指定, 未知的一些符号比如 printf
            return "NOTYPE";
        case STT_OBJECT:
            // 符号与数据对象相关联,如变量、数组等等.
            return "OBJECT";
        case STT_FUNC:
            // 符号与函数或其他可执行代码相关联
            return "FUNC";
        case STT_SECTION:
            // 该符号与一个章节相关联.这种类型的符号表项主要用于重新定位,通常与 STB_LOCAL 绑定.
            return "SECTION";
        case STT_FILE:
            // 文件符号具有 STB_LOCAL 绑定功能,其分区索引为 SHN_ABS,如果存在,则位于文件的其他 STB_LOCAL 符号之前.
            // 如果存在,它位于文件的其他 STB_LOCAL 符号之前
            return "FILE";
        case STT_COMMON:
            // 符号是一种常见的数据对象
            return "COMMON";
        case STT_TLS:
            // 符号是线程本地数据对象
            return "TLS";
        default:
            return "UNKNOWN";
    }
}


char *get_symbol_bind(int st_info) {
    switch (st_info) {
        case STB_LOCAL:
            // 本地符号在包含其定义的对象文件之外是不可见的.
            // 定义的对象文件外是不可见的.同名的局部符号可存在于多个文件中
            // 而不会相互干扰.
            return "LOCAL";
        case STB_GLOBAL:
            // 全局符号对合并的所有对象文件都是可见的.一个文件的
            // 全局符号的定义将满足另一个文件对同一全局符号的未定义引用.
            // 对同一全局符号的未定义引用.
            return "GLOBAL";
        case STB_WEAK:
            // 弱符号类似于全局符号,但其定义的优先级较低.
            return "WEAK";
        default:
            return "UNKNOWN";
    }
}

char *get_symbol_vis(int st_other) {
    switch (st_other) {
        case STV_DEFAULT:
            return "DEFAULT";
        case STV_INTERNAL:
            return "INTERNAL";
        case STV_HIDDEN:
            return "HIDDEN";
        case STV_PROTECTED:
            return "PROTECTED";
        default:
            return "UNKNOWN";
    }
}

char *get_symbol_ndx(int st_shndx) {
    static char buf[10];
    memset(buf, 0, 10);
    int i = 8;
    buf[9] = 0;
    switch (st_shndx) {
        case SHN_ABS:
            return "ABS";
        case SHN_COMMON:
            return "COM";
        case SHN_UNDEF:
            return "UND";
        default: {
            // 正常情况
            while (st_shndx) {
                buf[i--] = '0' + st_shndx % 10;
                st_shndx /= 10;
            }
            return buf + i + 1;
        }
    }
}


int print_elf_symbol_table(ELF_IMG *elf_img) {
    int section_number = elf_img->ehdr.e_shnum;
    Elf64_Sym *symtab_addr;  // 符号表指针
    int symtab_number;       // 符号表表项的个数
    for (int i = 0; i < section_number; i++) {
        Elf64_Shdr *shdr = &elf_img->shdr[i];
        // SHT_SYMTAB 和 SHT_DYNSYM 类型的段是符号表
        if ((shdr->sh_type == SHT_SYMTAB) || (shdr->sh_type == SHT_DYNSYM)) {
            // 符号表的段名
            char *section_name = elf_strptr(elf_img->elf, elf_img->ehdr.e_shstrndx, shdr->sh_name); // 从指定的字符串表中通过偏移获取字符串
            // sh_link 指向符号表对应的字符串表
            Elf64_Shdr *strtab = &elf_img->shdr[shdr->sh_link];

            // 定位到当前段的起始地址
            symtab_addr = (Elf64_Sym *)((char*)elf_img->addr + shdr->sh_offset);
            // 通过 sh_size 和 Elf64_Sym 结构体大小计算表项数量
            symtab_number = shdr->sh_size / sizeof(Elf64_Sym);
            printf("\nSymbol table '%s' contains %d %s:\n",
                   section_name,
                   symtab_number,
                   symtab_number == 1 ? "entry" : "entries");
            printf("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n");
            for (int j = 0; j < symtab_number; j++) {
                // 对于每一个表项 symtab_addr[j] => Elf64_Sym
                // st_info 的低4位用于符号类型 0-3      => ELF64_ST_TYPE
                // st_info 的高4位用于符号绑定信息 4-7  => ELF64_ST_BIND
                char *symbol_type = get_symbol_type(ELF64_ST_TYPE(symtab_addr[j].st_info));
                char *symbol_bind = get_symbol_bind(ELF64_ST_BIND(symtab_addr[j].st_info));
                char *symbol_visibility = get_symbol_vis(symtab_addr[j].st_other);  // 用于控制符号可见性
                char *symbol_ndx = get_symbol_ndx(symtab_addr[j].st_shndx);
                char *symbol_name;
                // 对于 st_name 的值不为0的符号或者 ABS, 去对应的 .strtab 中找
                if (symtab_addr[j].st_name || symtab_addr[j].st_shndx == SHN_ABS) {
                    symbol_name = (char *)((char*)elf_img->addr + strtab->sh_offset + symtab_addr[j].st_name);
                } else {
                    // 为 0 说明是一个特殊符号, 用 symbol_ndx 去段表字符串表中找
                    symbol_name = (char *)((char*)elf_img->addr + elf_img->shstrtab_offset +
                                           elf_img->shdr[symtab_addr[j].st_shndx].sh_name);
                }
                if (!truncated && strlen(symbol_name) > 21) {
                    char short_symbol_name[22];
                    strncpy(short_symbol_name, symbol_name, 16);
                    strncpy(short_symbol_name + 16, "[...]", 6);
                    short_symbol_name[21] = 0;
                    symbol_name = short_symbol_name;
                }
                printf("%6d: %016lx %5ld %-8s%-6s %-7s %4s %s\n",
                       j,
                       symtab_addr[j].st_value,
                       symtab_addr[j].st_size,
                       symbol_type,
                       symbol_bind,
                       symbol_visibility,
                       symbol_ndx,
                       symbol_name);
            }
        }
    }
    return 0;
}


// ============================================================================ //
// loader API 实现 --> 定义 src/controller/loader/loader.h
// ============================================================================ //


long parse_file(char *file_path) {
    // Elf *elf;
    int fd;
    char *shname, *shname_prog;
    Elf_Data *data;
    GElf_Shdr shdr;
    size_t file_size = 0;
    if (elf_version(EV_CURRENT) == EV_NONE)
        return 0;
    fd = open(file_path, O_RDONLY, 0); // 打开elf文件
    Assertf(fd >= 0, "Can not open '%s'", file_path);
    elf_img.elf = elf_begin(fd, ELF_C_READ, NULL); // 获取elf描述符,使用‘读取’的方式
    Assert(elf_img.elf, "Can not get elf desc");
    Assert(gelf_getehdr(elf_img.elf, &elf_img.ehdr) == &elf_img.ehdr, "Can not get elf ehdr");

 
    printf("File Name: %s\n", file_path);
    print_elf_header_info(elf_img.ehdr);
    
    elf_img.shdr = (GElf_Shdr *)malloc(sizeof(GElf_Shdr) * elf_img.ehdr.e_shnum);
    for (int i = 1; i < elf_img.ehdr.e_shnum; i++) {
        if(get_section(elf_img.elf, i, &elf_img.ehdr, &shname, &elf_img.shdr[i], &data)) {
            continue;
        }
        file_size += data->d_size;
    }
    print_elf_section_table(&elf_img);
    Logg("Success load file: %s, size: %ld", file_path, (long)file_size);
    return (long)file_size;
}

// load and parse a ELF file, print ehdr infomation
