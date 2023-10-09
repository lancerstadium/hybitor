/// \file emulator/syscall.hpp
/// \brief RISC-V64 syscall 模拟

#ifndef EMULATOR_SYSCALL_HPP
#define EMULATOR_SYSCALL_HPP

#include <sys/stat.h>
#include <sys/time.h>

#include "emulator/cpu.hpp"

extern "C" {

// Copied from https://github.com/riscv-software-src/riscv-pk
#define SYS_exit 93
#define SYS_exit_group 94
#define SYS_getpid 172
#define SYS_kill 129
#define SYS_tgkill 131
#define SYS_read 63
#define SYS_write 64
#define SYS_openat 56
#define SYS_close 57
#define SYS_lseek 62
#define SYS_brk 214
#define SYS_linkat 37
#define SYS_unlinkat 35
#define SYS_mkdirat 34
#define SYS_renameat 38
#define SYS_chdir 49
#define SYS_getcwd 17
#define SYS_fstat 80
#define SYS_fstatat 79
#define SYS_faccessat 48
#define SYS_pread 67
#define SYS_pwrite 68
#define SYS_uname 160
#define SYS_getuid 174
#define SYS_geteuid 175
#define SYS_getgid 176
#define SYS_getegid 177
#define SYS_gettid 178
#define SYS_sysinfo 179
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_mremap 216
#define SYS_mprotect 226
#define SYS_prlimit64 261
#define SYS_getmainvars 2011
#define SYS_rt_sigaction 134
#define SYS_writev 66
#define SYS_gettimeofday 169
#define SYS_times 153
#define SYS_fcntl 25
#define SYS_ftruncate 46
#define SYS_getdents 61
#define SYS_dup 23
#define SYS_dup3 24
#define SYS_readlinkat 78
#define SYS_rt_sigprocmask 135
#define SYS_ioctl 29
#define SYS_getrlimit 163
#define SYS_setrlimit 164
#define SYS_getrusage 165
#define SYS_clock_gettime 113
#define SYS_set_tid_address 96
#define SYS_set_robust_list 99
#define SYS_madvise 233
#define SYS_statx 291

#define OLD_SYSCALL_THRESHOLD 1024
#define SYS_open 1024
#define SYS_link 1025
#define SYS_unlink 1026
#define SYS_mkdir 1030
#define SYS_access 1033
#define SYS_stat 1038
#define SYS_lstat 1039
#define SYS_time 1062

/// 获取寄存器值
#define GET(reg, name) u64 name = cpu.cpu_get_gp_reg(reg);

/// syscall函数指针
typedef u64 (* syscall_t)(CPU &cpu);

/// @brief 未实现方法
/// @param vm 虚拟机对象
/// @return 
static u64 sys_unimplemented(CPU &cpu) {
    fatalf("unimplemented syscall: %lu", (unsigned long)cpu.cpu_get_gp_reg(a7));
}

/**
 * 退出程序：
 * ret = exit(code);
 */
static u64 sys_exit(CPU &cpu) {
    GET(a0, code);
    exit(code);
}

/**
 * 关闭文件：
 * ret = close(fd);
 */
static u64 sys_close(CPU &cpu) {
    GET(a0, fd);
    if (fd > 2) return close(fd);
    return 0;
}

/**
 * 写入文件：
 * ret = write(fd, data_ptr, len);
 */
static u64 sys_write(CPU &cpu) {
    GET(a0, fd); GET(a1, ptr); GET(a2, len);
    return write(fd, (void *)TO_HOST(ptr), (size_t)len);
}

/**
 * 文件获取：
 * ret = fstat(fd, addr);
 * ---------------^u64
 */
static u64 sys_fstat(CPU &cpu) {
    GET(a0, fd); GET(a1, addr);
    return fstat(fd, (struct stat *)TO_HOST(addr));
}

static u64 sys_gettimeofday(CPU &cpu) {
    GET(a0, tv_addr); GET(a1, tz_addr);
    struct timeval *tv = (struct timeval *)TO_HOST(tv_addr);
    struct timezone *tz = NULL;
    if (tz_addr != 0) tz = (struct timezone *)TO_HOST(tz_addr);
    return gettimeofday(tv, tz);
}

/**
 * 申请/释放内存
 * malloc/free
 */
static u64 sys_brk(CPU &cpu) {
    GET(a0, addr);
    if (addr == 0) addr = cpu.bus.dram.alloc;
    assert(addr >= cpu.bus.dram.base);
    i64 incr = (i64)addr - cpu.bus.dram.alloc;
    cpu.bus.dram.mem_alloc(incr);
    return addr;
}

// the O_* macros is OS dependent.
// here is a workaround to convert newlib flags to the host.
#define NEWLIB_O_RDONLY   0x0
#define NEWLIB_O_WRONLY   0x1
#define NEWLIB_O_RDWR     0x2
#define NEWLIB_O_APPEND   0x8
#define NEWLIB_O_CREAT  0x200
#define NEWLIB_O_TRUNC  0x400
#define NEWLIB_O_EXCL   0x800
#define REWRITE_FLAG(flag) if (flags & NEWLIB_ ##flag) hostflags |= flag;

static int convert_flags(int flags) {
    int hostflags = 0;
    REWRITE_FLAG(O_RDONLY);
    REWRITE_FLAG(O_WRONLY);
    REWRITE_FLAG(O_RDWR);
    REWRITE_FLAG(O_APPEND);
    REWRITE_FLAG(O_CREAT);
    REWRITE_FLAG(O_TRUNC);
    REWRITE_FLAG(O_EXCL);
    return hostflags;
}

static u64 sys_openat(CPU &cpu) {
    GET(a0, dirfd); GET(a1, nameptr); GET(a2, flags); GET(a3, mode);
    return openat(dirfd, (char *)TO_HOST(nameptr), convert_flags(flags), mode);
}

static u64 sys_open(CPU &cpu) {
    GET(a0, nameptr); GET(a1, flags); GET(a2, mode);
    u64 ret = open((char *)TO_HOST(nameptr), convert_flags(flags), (mode_t)mode);
    return ret;
}

static u64 sys_lseek(CPU &cpu) {
    GET(a0, fd); GET(a1, offset); GET(a2, whence);
    return lseek(fd, offset, whence);
}

static u64 sys_read(CPU &cpu) {
    GET(a0, fd); GET(a1, bufptr); GET(a2, count);
    return read(fd, (char *)TO_HOST(bufptr), (size_t)count);
}

/// @brief 系统调用映射表
static syscall_t syscall_table[] = {
    [SYS_exit] =           sys_exit,
    [SYS_exit_group] =     sys_exit,
    [SYS_read] =           sys_read,
    [SYS_pread] =          sys_unimplemented,
    [SYS_write] =          sys_write,
    [SYS_openat] =         sys_openat,
    [SYS_close] =          sys_close,
    [SYS_fstat] =          sys_fstat,
    [SYS_statx] =          sys_unimplemented,
    [SYS_lseek] =          sys_lseek,
    [SYS_fstatat] =        sys_unimplemented,
    [SYS_linkat] =         sys_unimplemented,
    [SYS_unlinkat] =       sys_unimplemented,
    [SYS_mkdirat] =        sys_unimplemented,
    [SYS_renameat] =       sys_unimplemented,
    [SYS_getcwd] =         sys_unimplemented,
    [SYS_brk] =            sys_brk,
    [SYS_uname] =          sys_unimplemented,
    [SYS_getpid] =         sys_unimplemented,
    [SYS_getuid] =         sys_unimplemented,
    [SYS_geteuid] =        sys_unimplemented,
    [SYS_getgid] =         sys_unimplemented,
    [SYS_getegid] =        sys_unimplemented,
    [SYS_gettid] =         sys_unimplemented,
    [SYS_tgkill] =         sys_unimplemented,
    [SYS_mmap] =           sys_unimplemented,
    [SYS_munmap] =         sys_unimplemented,
    [SYS_mremap] =         sys_unimplemented,
    [SYS_mprotect] =       sys_unimplemented,
    [SYS_rt_sigaction] =   sys_unimplemented,
    [SYS_gettimeofday] =   sys_gettimeofday,
    [SYS_times] =          sys_unimplemented,
    [SYS_writev] =         sys_unimplemented,
    [SYS_faccessat] =      sys_unimplemented,
    [SYS_fcntl] =          sys_unimplemented,
    [SYS_ftruncate] =      sys_unimplemented,
    [SYS_getdents] =       sys_unimplemented,
    [SYS_dup] =            sys_unimplemented,
    [SYS_dup3] =           sys_unimplemented,
    [SYS_rt_sigprocmask] = sys_unimplemented,
    [SYS_clock_gettime] =  sys_unimplemented,
    [SYS_chdir] =          sys_unimplemented,
};

/// @brief 旧系统调用表
static syscall_t old_syscall_table[] = {
    [-OLD_SYSCALL_THRESHOLD + SYS_open] =   sys_open,
    [-OLD_SYSCALL_THRESHOLD + SYS_link] =   sys_unimplemented,
    [-OLD_SYSCALL_THRESHOLD + SYS_unlink] = sys_unimplemented,
    [-OLD_SYSCALL_THRESHOLD + SYS_mkdir] =  sys_unimplemented,
    [-OLD_SYSCALL_THRESHOLD + SYS_access] = sys_unimplemented,
    [-OLD_SYSCALL_THRESHOLD + SYS_stat] =   sys_unimplemented,
    [-OLD_SYSCALL_THRESHOLD + SYS_lstat] =  sys_unimplemented,
    [-OLD_SYSCALL_THRESHOLD + SYS_time] =   sys_unimplemented,
};

u64 do_syscall(CPU &cpu, u64 n) {
    syscall_t f = NULL;
    if (n < ARRAY_SIZE(syscall_table))
        f = syscall_table[n];
    else if (n - OLD_SYSCALL_THRESHOLD < ARRAY_SIZE(old_syscall_table))
        f = old_syscall_table[n - OLD_SYSCALL_THRESHOLD];

    if (!f) fatal("unknown syscall");

    return f(cpu);
}

} // extern "C"

#endif