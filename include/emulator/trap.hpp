/// \file emulator/trap.hpp
/// \brief RISC-V64 trap 模拟

#ifndef EMULATOR_TRAP_HPP
#define EMULATOR_TRAP_HPP

#include "emulator/cpu.hpp"

enum TRAP {
    Contained,
    Requested,
    Invisible,
    Fatal
};

enum EXCEPTION {
    Instruction_address_misaligned = 0,
    Instruction_access_fault,
    Illegal_instruction,
    Breakpoint,
    Load_address_misaligned,
    Load_access_fault,
    Store_AMO_address_misaligned,
    Store_AMO_access_fault,
    Environment_call_from_U_mode,
    Environment_call_from_S_mode,
    Environment_call_from_M_mode = 11,
    Instruction_page_fault,
    Load_page_fault,
    Store_AMO_page_fault = 15 
};

#endif // EMULATOR_DECORDER_HPP