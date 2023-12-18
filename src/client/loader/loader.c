/**
 * @brief hybitor loader 加载器器定义
 * @file src/client/loader/loader.c
 * @author lancerstadium
 * @date 2023-10-18
*/

#include "loader.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>


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





#define ELF_TBSS_SPECIAL(sec_hdr, segment) \
    (((sec_hdr)->sh_flags & SHF_TLS) != 0 && (sec_hdr)->sh_type == SHT_NOBITS && (segment)->p_type != PT_TLS)

#define ELF_SECTION_SIZE(sec_hdr, segment) (ELF_TBSS_SPECIAL(sec_hdr, segment) ? 0 : (sec_hdr)->sh_size)

typedef uint64_t bfd_vma;

#define ELF_SECTION_IN_SEGMENT_1(sec_hdr, segment, check_vma, strict)                                                 \
    ((/* Only PT_LOAD, PT_GNU_RELRO and PT_TLS segments can contain                                                   \
         SHF_TLS sections.  */                                                                                        \
      ((((sec_hdr)->sh_flags & SHF_TLS) != 0) &&                                                                      \
       ((segment)->p_type == PT_TLS || (segment)->p_type == PT_GNU_RELRO ||                                           \
        (segment)->p_type == PT_LOAD)) /* PT_TLS segment contains only SHF_TLS sections, PT_PHDR no                   \
                                          sections at all.  */                                                        \
      || (((sec_hdr)->sh_flags & SHF_TLS) == 0 && (segment)->p_type != PT_TLS &&                                      \
          (segment)->p_type != PT_PHDR)) /* PT_LOAD and similar segments only have SHF_ALLOC sections.  */            \
     && !(((sec_hdr)->sh_flags & SHF_ALLOC) == 0 &&                                                                   \
          ((segment)->p_type == PT_LOAD || (segment)->p_type == PT_DYNAMIC || (segment)->p_type == PT_GNU_EH_FRAME || \
           (segment)->p_type == PT_GNU_STACK || (segment)->p_type == PT_GNU_RELRO ||                                  \
           (segment)->p_type == PT_GNU_SFRAME ||                                                                      \
           ((segment)->p_type >= PT_GNU_MBIND_LO &&                                                                   \
            (segment)->p_type <= PT_GNU_MBIND_HI))) /* Any section besides one of type SHT_NOBITS must have file      \
                                                       offsets within the segment.  */                                \
     && ((sec_hdr)->sh_type == SHT_NOBITS ||                                                                          \
         ((bfd_vma)(sec_hdr)->sh_offset >= (segment)->p_offset &&                                                     \
          (!(strict) || ((sec_hdr)->sh_offset - (segment)->p_offset <= (segment)->p_filesz - 1)) &&                   \
          (((sec_hdr)->sh_offset - (segment)->p_offset + ELF_SECTION_SIZE(sec_hdr, segment)) <=                       \
           (segment)->p_filesz))) /* SHF_ALLOC sections must have VMAs within the segment.  */                        \
     && (!(check_vma) || ((sec_hdr)->sh_flags & SHF_ALLOC) == 0 ||                                                    \
         ((sec_hdr)->sh_addr >= (segment)->p_vaddr &&                                                                 \
          (!(strict) || ((sec_hdr)->sh_addr - (segment)->p_vaddr <= (segment)->p_memsz - 1)) &&                       \
          (((sec_hdr)->sh_addr - (segment)->p_vaddr + ELF_SECTION_SIZE(sec_hdr, segment)) <=                          \
           (segment)->p_memsz))) /* No zero size sections at start or end of PT_DYNAMIC nor                           \
                                    PT_NOTE.  */                                                                      \
     &&                                                                                                               \
     (((segment)->p_type != PT_DYNAMIC && (segment)->p_type != PT_NOTE) || (sec_hdr)->sh_size != 0 ||                 \
      (segment)->p_memsz == 0 ||                                                                                      \
      (((sec_hdr)->sh_type == SHT_NOBITS || ((bfd_vma)(sec_hdr)->sh_offset > (segment)->p_offset &&                   \
                                             ((sec_hdr)->sh_offset - (segment)->p_offset < (segment)->p_filesz))) &&  \
       (((sec_hdr)->sh_flags & SHF_ALLOC) == 0 || ((sec_hdr)->sh_addr > (segment)->p_vaddr &&                         \
                                                   ((sec_hdr)->sh_addr - (segment)->p_vaddr < (segment)->p_memsz))))))

#define ELF_SECTION_IN_SEGMENT_STRICT(sec_hdr, segment) (ELF_SECTION_IN_SEGMENT_1(sec_hdr, segment, 1, 1))



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

static void print_elf_header_info(ELF_IMG elf_img) {
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf("%2.2x ", elf_img.ehdr.e_ident[i]);
    }
    printf("\n");
    printf(ELF_PRINT_FORMAT, "Class:", get_class(elf_img.ehdr));
    printf(ELF_PRINT_FORMAT, "Data:", get_data_endian(elf_img.ehdr));
    printf("  %-35s%d (%s)\n", "Version:", elf_img.ehdr.e_version, get_version(elf_img.ehdr));
    printf(ELF_PRINT_FORMAT, "OS/ABI:", get_osabi(elf_img.ehdr));
    printf("  %-35s%u\n", "ABI version:", elf_img.ehdr.e_ident[EI_ABIVERSION]);
    printf(ELF_PRINT_FORMAT, "Type:", get_type(elf_img.ehdr));
    printf(ELF_PRINT_FORMAT, "Machine:", get_arch(elf_img.ehdr));
    printf("  Version:                           0x%x\n", elf_img.ehdr.e_version);
    printf("  Entry point address:               " FMT_PADDR "\n", (unsigned int)elf_img.ehdr.e_entry);
    printf("  Start of program headers:          %lld (bytes into file)\n", (unsigned long long)elf_img.ehdr.e_phoff);
    printf("  Start of section headers:          %lld (bytes into file)\n", (unsigned long long)elf_img.ehdr.e_shoff);
    printf("  Flags:                             0x%x\n", elf_img.ehdr.e_flags);
    printf("  Size of this header:               %d (bytes)\n", elf_img.ehdr.e_ehsize);
    printf("  Size of program headers:           %d (bytes)\n", elf_img.ehdr.e_phentsize);
    printf("  Number of program headers:         %d\n", elf_img.ehdr.e_phnum);
    printf("  Size of section headers:           %d (bytes)\n", elf_img.ehdr.e_shentsize);
    printf("  Number of section headers:         %d\n", elf_img.ehdr.e_shnum);
    printf("  Section header string table index: %d\n", elf_img.ehdr.e_shstrndx);
}



// ============================================================================ //
// loader -> section
// ============================================================================ //


static char *get_section_type(Elf64_Word section_type) {
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
static char *get_section_flag(Elf64_Xword section_flag) {
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
static int print_elf_section_table(ELF_IMG elf_img) {
    int section_number = elf_img.ehdr.e_shnum;
    printf("There are %d section headers, starting at offset " FMT_PADDR "\n", section_number, (unsigned int) elf_img.ehdr.e_shoff);

    printf("\nSection %s:\n", section_number == 1 ? "Header" : "Headers");

    printf("  [Nr] Name              Type             Address           Offset\n");
    printf("       Size              EntSize          Flags  Link  Info  Align\n");
    for (int i = 0; i < section_number; i++) {
        GElf_Shdr *shdr = &elf_img.shdr[i];
        char number[3] = " x";
        if (i / 10) {
            number[0] = '0' + i / 10;
        }
        number[1] = '0' + i % 10;
        Assert(shdr, "shdr is null");
        char *section_type = get_section_type(shdr->sh_type);
        char *section_flag = get_section_flag(shdr->sh_flags);
        // 段名的获取方式是通过 shstrtab + sh_name(偏移地址) 得到的
        // 从指定的字符串表中通过偏移获取字符串
        char *section_name = (char *)((char*)elf_img.addr + elf_img.shstrtab_offset + shdr->sh_name); 
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

static char *get_symbol_type(int st_info) {
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


static char *get_symbol_bind(int st_info) {
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

static char *get_symbol_vis(int st_other) {
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

static char *get_symbol_ndx(GElf_Half st_shndx) {
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


static int print_elf_symbol_table(ELF_IMG elf_img) {
    int section_number = elf_img.ehdr.e_shnum;
    Elf64_Sym *symtab_addr;  // 符号表指针
    int symtab_number;       // 符号表表项的个数
    for (int i = 0; i < section_number; i++) {
        GElf_Shdr *shdr = &elf_img.shdr[i];
        // SHT_SYMTAB 和 SHT_DYNSYM 类型的段是符号表
        if ((shdr->sh_type == SHT_SYMTAB) || (shdr->sh_type == SHT_DYNSYM)) {
            // 符号表的段名
            char *section_name = (char *)((char*)elf_img.addr + elf_img.shstrtab_offset + shdr->sh_name);
            // sh_link 指向符号表对应的字符串表
            GElf_Shdr *strtab = &elf_img.shdr[shdr->sh_link];
            // 定位到当前段的起始地址
            symtab_addr = (Elf64_Sym *)((char*)elf_img.addr + shdr->sh_offset);
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
                    symbol_name = (char *)((char*)elf_img.addr + strtab->sh_offset + symtab_addr[j].st_name);
                } else {
                    // 为 0 说明是一个特殊符号, 用 symbol_ndx 去段表字符串表中找
                    symbol_name = (char *)((char*)elf_img.addr + elf_img.shstrtab_offset +
                                           elf_img.shdr[symtab_addr[j].st_shndx].sh_name);
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
// loader program header
// ============================================================================ //

static char *get_program_interpreter(ELF_IMG elf_img) {
    int section_number = elf_img.ehdr.e_shnum;
    for (int i = 0; i < section_number; i++) {
        GElf_Shdr *shdr = &elf_img.shdr[i];
        if (shdr->sh_type == SHT_PROGBITS) {
            char *section_name = (char *)((char*)elf_img.addr + elf_img.shstrtab_offset + shdr->sh_name);
            if (!strcmp(section_name, ".interp")) {
                return (char *)((char*)elf_img.addr + shdr->sh_addr);
            }
        }
    }
    return "";
}



static char *get_phdr_type(uint32_t p_type) {
    switch (p_type) {
        case PT_NULL:
            return "NULL";
        case PT_LOAD:
            return "LOAD";
        case PT_DYNAMIC:
            return "DYNAMIC";
        case PT_INTERP:
            return "INTERP";
        case PT_NOTE:
            return "NOTE";
        case PT_SHLIB:
            return "SHLIB";
        case PT_PHDR:
            return "PHDR";
        case PT_GNU_STACK:
            return "GNU_STACK";
        case PT_LOPROC:
            return "LOPROC";
        case PT_HIPROC:
            return "HIPROC";
        case PT_GNU_RELRO:
            return "GNU_RELRO";
        case PT_GNU_EH_FRAME:
            return "GNU_EH_FRAME";
        case PT_GNU_PROPERTY:
            return "GNU_PROPERTY";
        default:
            return "";
    }
}

static char *get_phdr_flag(uint32_t p_flags) {
    static char flags[3] = "   ";
    memset(flags, ' ', 3);
    if (p_flags & PF_R) {
        flags[0] = 'R';
    }
    if (p_flags & PF_W) {
        flags[1] = 'W';
    }
    if (p_flags & PF_X) {
        flags[2] = 'E';
    }
    return flags;
}



static void print_elf_program_header(ELF_IMG elf_img) {
    if (elf_img.ehdr.e_phnum == 0) {
        printf("\nThere are no program headers in this file.\n");
        return;
    }
    int ph_entry_number = 0;
    if (elf_img.ehdr.e_phnum == PN_XNUM) {
        // ...
    } else {
        ph_entry_number = elf_img.ehdr.e_phnum;
    }

    char *elf_type_name = get_type(elf_img.ehdr);
    printf("\nElf file type is %s\n", elf_type_name);
    printf("Entry point " FMT_PADDR "\n", (unsigned int)elf_img.ehdr.e_entry);
    printf("There are %d program headers, starting at offset %lld\n",
           ph_entry_number,
           (unsigned long long)elf_img.ehdr.e_phoff);
    printf("\nProgram Headers:\n");
    printf("  Type           Offset             VirtAddr           PhysAddr\n");
    printf("                 FileSiz            MemSiz              Flags  Align\n");
    // printf("  %-15s");

    GElf_Phdr *phdr = (GElf_Phdr *)((char*)elf_img.addr + elf_img.ehdr.e_phoff);
    for (int i = 0; i < ph_entry_number; i++) {
        char *phdr_type = get_phdr_type(phdr[i].p_type);
        char *phdr_flag = get_phdr_flag(phdr[i].p_flags);
        printf("  %-15s0x%016lx 0x%016lx 0x%016lx\n", phdr_type, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr);
        printf("                 0x%016lx 0x%016lx  %-7s0x%lx\n",
               phdr[i].p_filesz,
               phdr[i].p_memsz,
               phdr_flag,
               phdr[i].p_align);
        if (phdr[i].p_type == PT_INTERP) {
            char *program_interpreter_path = get_program_interpreter(elf_img);
            printf("      [Requesting program interpreter: %s]\n", program_interpreter_path);
        }
    }

    printf("\n Section to Segment mapping:\n");
    printf("  Segment Sections...\n");
    phdr = (GElf_Phdr *)((char*)elf_img.addr + elf_img.ehdr.e_phoff);
    for (int i = 0; i < ph_entry_number; i++) {
        printf("   %02d     ", i);
        GElf_Phdr *segment = &phdr[i];
        
        for (int j = 1; j < elf_img.ehdr.e_shnum; j++) {
            GElf_Shdr *section = &elf_img.shdr[j];
            if (!ELF_TBSS_SPECIAL(section, segment) && ELF_SECTION_IN_SEGMENT_STRICT(section, segment)) {
                char *section_name =
                    (char *)((char*)elf_img.addr + elf_img.shstrtab_offset + section->sh_name);
                printf("%s ", section_name);
            }
        }
        printf("\n");
    }
}



// ============================================================================ //
// loader API 实现 --> 声明 src/client/loader/loader.h
// ============================================================================ //


static long load_img() {
    if (elf_img.img_file == NULL) {
        Log("No image is given. Use the default build-in image.");
        return 4096; // built-in image size
    }

    FILE *fp = fopen(elf_img.img_file, "rb");
    Assertf(fp, "Can not open '%s'", elf_img.img_file);

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);

    Logg("The image is %s, size = %ld", elf_img.img_file, size);

    fseek(fp, 0, SEEK_SET);
    int ret = fread(guest_to_host(RESET_VECTOR), size, 1, fp);
    assert(ret == 1);

    fclose(fp);
    return size;
}

long load_img_file(char *file_path) {
    // 1. 读取文件
    Elf *elf;
    int fd;
    char *shname;
    Elf_Data *data;
    if (elf_version(EV_CURRENT) == EV_NONE)
        return 0;
    fd = open(file_path, O_RDONLY, 0); // 打开elf文件
    Assertf(fd >= 0, "Can not open '%s'", file_path);
    
    // 2. 对 ELF 文件做完整的内存映射, 保存在 elf_img.addr 中, 方便后面寻址
    elf_img.size = lseek(fd, 0, SEEK_END);
    // void *addr = mmap(guest_to_host(CONFIG_MBASE), elf_img.size, PROT_READ, MAP_PRIVATE, fd, 0);
    void *addr = mmap((void *)guest_to_host(CONFIG_MBASE), elf_img.size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, fd, 0);
    if(addr == MAP_FAILED){
        munmap(addr, elf_img.size);
        close(fd);
        Warningf("File mmap fail: %s", file_path);
        return 0;
    }
    elf_img.addr = addr;

    load_img();                            // --------------------------
    
    
    // 3. 读取 ELF 头，保存在 elf_img.ehdr中
    elf = elf_begin(fd, ELF_C_READ, NULL); // 获取elf描述符,使用‘读取’的方式
    Assert(elf, "Can not get elf desc");
    Assert(gelf_getehdr(elf, &elf_img.ehdr) == &elf_img.ehdr, "Can not get elf ehdr");

    // 4. 读取所有端表信息保存在 shdr 中
    elf_img.shdr = (GElf_Shdr *)malloc(sizeof(GElf_Shdr) * elf_img.ehdr.e_shnum);
    for (int i = 1; i < elf_img.ehdr.e_shnum; i++) {
        if(get_section(elf, i, &elf_img.ehdr, &shname, &elf_img.shdr[i], &data)) {
            continue;
        }
    }

    cpu.pc += elf_img.ehdr.e_entry; // 新增pc值

    // 5. 获取段表字符串表的偏移量
    elf_img.shstrtab_offset = elf_img.shdr[elf_img.ehdr.e_shstrndx].sh_offset;  

    // 6. 打印信息
    Logg("Success load file: %s, size: %ld", elf_img.img_file, (long)elf_img.size);
    display_img_file_info();

    // 7. 释放资源
    close(fd);
    free(elf);

    return (long)elf_img.size;
}




long free_img_file(char *file_path) {
    if(elf_img.size > 0) {
        munmap(elf_img.addr, elf_img.size);
        // free(&elf_img.ehdr); 这里不能释放
        free(elf_img.shdr);
        elf_img.shstrtab_offset = 0;
        elf_img.size = 0;
        Logg("Success free file: %s, now size: %ld", elf_img.img_file, (long)elf_img.size);
    } else {
        Warningf("No file to free: %s", elf_img.img_file);
    }
    return (long)elf_img.size;
}

void display_img_file_info() {
    printf("ELF file info: \n");
    printf("  filename: %s\n", elf_img.img_file);
    printf("  arch: %s\n", get_arch(elf_img.ehdr));
    printf("  addr: %p\n", elf_img.addr);
    printf("  entry point: " FMT_WORD "\n", elf_img.ehdr.e_entry);
    printf("  size: %ld\n", elf_img.size);
}

void display_img_header_info() {
    print_elf_header_info(elf_img);
}

void display_img_section_info() {
    print_elf_section_table(elf_img);
}

void display_img_symbol_info() {
    print_elf_symbol_table(elf_img);
}

void display_img_program_info() {
    print_elf_program_header(elf_img);
}


void set_load_img() {
    if (elf_img.img_file == NULL) {
        Logy("Img_file: %s, Use default img: `%s`", elf_img.img_file, default_img_file);
        elf_img.img_file = default_img_file;
    } else {
        Logg("Set img_file: `%s`", elf_img.img_file);
    }
}

void init_load_img() {
    set_load_img();
    load_img_file(elf_img.img_file);
}

bool change_load_img(char *file_path) {
    FILE *fp = fopen(file_path, "rb");
    if(!fp) {
        Logy("Can not open file: %s", file_path);
        return false;
    }
    fclose(fp);
    free_img_file(file_path);
    elf_img.img_file = file_path;
    Logg("Change img_file to: `%s`", elf_img.img_file);
    return true;
}


// load and parse a ELF file, print ehdr infomation
