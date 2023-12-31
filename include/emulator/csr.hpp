/// \file emulator/csr.hpp
/// \brief csr 模拟

#ifndef EMULATOR_CSR_HPP
#define EMULATOR_CSR_HPP

#include "tools/types.hpp"

/// @brief csr寄存器
enum csr_t {
    fflags = 0x001,
    frm    = 0x002,
    fcsr   = 0x003,
};


typedef struct CSR {
    u64 csr[4096];
} CSR;

enum CSR_ADDR {
    //unprivileged Counter/Timers
    cycle = 0xC00,
    time_c,
    instret,
    hpmcounter3,
    hpmcounter4,
    hpmcounter5,
    hpmcounter6,
    hpmcounter7,
    hpmcounter8,
    hpmcounter9,
    hpmcounter10,
    hpmcounter11,
    hpmcounter12,
    hpmcounter13,
    hpmcounter14,
    hpmcounter15,
    hpmcounter16,
    hpmcounter17,
    hpmcounter18,
    hpmcounter19,
    hpmcounter20,
    hpmcounter21,
    hpmcounter22,
    hpmcounter23,
    hpmcounter24,
    hpmcounter25,
    hpmcounter26,
    hpmcounter27,
    hpmcounter28,
    hpmcounter29,
    hpmcounter30,
    hpmcounter31,

    //supervisor trap setup
    sstatus = 0x100,
    sie = 0x104,
    stvec,
    scounteren,
    //supervisor configuration
    senvcfg = 0x10A,
    //supervisor trap handling
    sscratch = 0x140,
    sepc,
    scause,
    stval,
    sip,
    //supervisor protection and Translation
    satp = 0x180,
    //debug/trace registers
    scontext = 0x5A8,
    //machine information registers
    mvendorid = 0xF11,
    marchid,
    mimpid,
    mhartid,
    mconfigptr,
    //machine trap setup
    mstatus = 0x300,
    misa,
    medeleg,
    mideleg,
    mie,
    mtvec,
    mcounteren,
    //mstatush = 0x310,
    //machine trap handling
    mscratch = 0x340,
    mepc,
    mcause,
    mtval,
    mip,
    mtinst = 0x34A,
    mtval2,
    //machine configuration
    menvcfg = 0x30A,
    
    mseccfg = 0x747,
    //machine memory protection
    pmpcfg0 = 0x3A0,
    pmpcfg1,
    pmpcfg2,
    pmpcfg3,
    pmpcfg4,
    pmpcfg5,
    pmpcfg6,
    pmpcfg7,
    pmpcfg8,
    pmpcfg9,
    pmpcfg10,
    pmpcfg11,
    pmpcfg12,
    pmpcfg13,
    pmpcfg14,
    pmpcfg15,
    pmpaddr0,
    pmpaddr1,
    pmpaddr2,
    pmpaddr3,
    pmpaddr4,
    pmpaddr5,
    pmpaddr6,
    pmpaddr7,
    pmpaddr8,
    pmpaddr9,
    pmpaddr10,
    pmpaddr11,
    pmpaddr12,
    pmpaddr13,
    pmpaddr14,
    pmpaddr15,
    pmpaddr16,
    pmpaddr17,
    pmpaddr18,
    pmpaddr19,
    pmpaddr20,
    pmpaddr21,
    pmpaddr22,
    pmpaddr23,
    pmpaddr24,
    pmpaddr25,
    pmpaddr26,
    pmpaddr27,
    pmpaddr28,
    pmpaddr29,
    pmpaddr30,
    pmpaddr31,
    pmpaddr32,
    pmpaddr33,
    pmpaddr34,
    pmpaddr35,
    pmpaddr36,
    pmpaddr37,
    pmpaddr38,
    pmpaddr39,
    pmpaddr40,
    pmpaddr41,
    pmpaddr42,
    pmpaddr43,
    pmpaddr44,
    pmpaddr45,
    pmpaddr46,
    pmpaddr47,
    pmpaddr48,
    pmpaddr49,
    pmpaddr50,
    pmpaddr51,
    pmpaddr52,
    pmpaddr53,
    pmpaddr54,
    pmpaddr55,
    pmpaddr56,
    pmpaddr57,
    pmpaddr58,
    pmpaddr59,
    pmpaddr60,
    pmpaddr61,
    pmpaddr62,
    pmpaddr63
};



#endif // EMULATOR_CSR_HPP
