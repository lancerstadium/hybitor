/**
 * @file include/capstone2llvmir/powerpc/powerpc.h
 * @brief PowerPC specialization of translator's abstract public interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_POWERPC_POWERPC_H
#define CAPSTONE2LLVMIR_POWERPC_POWERPC_H

#include "capstone2llvmir/capstone2llvmir.h"
#include "capstone2llvmir/powerpc/powerpc_defs.h"


namespace capstone2llvmir {

/**
 * PowerPC specialization of translator's abstract public interface.
 */
class Capstone2LlvmIrTranslatorPowerpc : virtual public Capstone2LlvmIrTranslator
{

};

} // namespace capstone2llvmir


#endif
