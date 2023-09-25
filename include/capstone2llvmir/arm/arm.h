/**
 * @file include/capstone2llvmir/arm/arm.h
 * @brief ARM specialization of translator's abstract public interface.
 */

#ifndef CAPSTONE2LLVMIR_ARM_ARM_H
#define CAPSTONE2LLVMIR_ARM_ARM_H

#include "capstone2llvmir/arm/arm_defs.h"
#include "capstone2llvmir/capstone2llvmir.h"


namespace capstone2llvmir {

/**
 * ARM specialization of translator's abstract public interface.
 */
class Capstone2LlvmIrTranslatorArm : virtual public Capstone2LlvmIrTranslator
{

};

} // namespace capstone2llvmir


#endif
