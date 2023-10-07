/**
 * @file include/capstone2llvmir/powerpc/powerpc_defs.h
 * @brief Additional (on top of Capstone) definitions for PowerPC translator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_POWERPC_POWERPC_DEFS_H
#define CAPSTONE2LLVMIR_POWERPC_POWERPC_DEFS_H


enum ppc_cr_types
{
	PPC_CR_LT,
	PPC_CR_GT,
	PPC_CR_EQ,
	PPC_CR_SO,
};

#endif
