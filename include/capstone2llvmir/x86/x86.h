/**
 * @file include/capstone2llvmir/x86/x86.h
 * @brief x86 specialization of translator's abstract public interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_X86_X86_H
#define CAPSTONE2LLVMIR_X86_X86_H

#include <array>
#include <tuple>
#include <utility>

#include "capstone2llvmir/capstone2llvmir.h"
#include "capstone2llvmir/x86/x86_defs.h"


namespace capstone2llvmir {

/**
 * x86 specialization of translator's abstract public interface.
 */
class Capstone2LlvmIrTranslatorX86 : virtual public Capstone2LlvmIrTranslator
{
	public:
		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents a store of fp value to the x87 fpu stack slot?
		 */
		virtual bool isX87DataStoreFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a store of fp value to the x87 fpu
		 * stack slot?
		 */
		virtual bool isX87DataStoreFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call in
		 * the translated LLVM IR represents a store of fp value (call second
		 * argument) to the x87 fpu stack slot (call first argument).
		 * Function signature: @code{.cpp} void (i3, fp80) @endcode
		 */
		virtual llvm::Function* getX87DataStoreFunction() const = 0;

		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents a load of fp value from the x87 fpu stack slot?
		 */
		virtual bool isX87DataLoadFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a load of fp value from the x87 fpu stack
		 * slot?
		 */
		virtual bool isX87DataLoadFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call in
		 * the translated LLVM IR represents a load of fp value (call return
		 * value) from the x87 fpu stack slot (first argument).
		 * Function signature: @code{.cpp} fp80 (i3) @endcode
		 */
		virtual llvm::Function* getX87DataLoadFunction() const = 0;

		/**
		 * @return Capstone register that is parent to the specified Capstone
		 * register @p r. Register can be its own parent.
		 */
		virtual uint32_t getParentRegister(uint32_t r) const = 0;
};

} // namespace capstone2llvmir

#endif
