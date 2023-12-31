/**
 * @file include/capstone2llvmir/mips/mips.h
 * @brief MIPS specialization of translator's abstract public interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_MIPS_MIPS_H
#define RETDEC_CAPSTONE2LLVMIR_MIPS_MIPS_H

#include "capstone2llvmir/capstone2llvmir.h"
#include "capstone2llvmir/mips/mips_defs.h"


namespace capstone2llvmir {

/**
 * MIPS specialization of translator's abstract public interface.
 */
class Capstone2LlvmIrTranslatorMips : virtual public Capstone2LlvmIrTranslator
{

};

} // namespace capstone2llvmir

#endif
