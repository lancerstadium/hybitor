/**
 * @file include/capstone2llvmir/exceptions.h
 * @brief Capstone2llmvir库中使用的异常定义。
 */

#ifndef CAPSTONE2LLVMIR_EXCEPTIONS_H
#define CAPSTONE2LLVMIR_EXCEPTIONS_H

#include <cassert>
#include <sstream>
#include <stdexcept>


#include <capstone/capstone.h>

namespace capstone2llvmir {


/// @brief Capstone2llvmIr的基本错误类，不该被抛出
class BaseError : public std::exception
{
	public:
		virtual ~BaseError() = default;
};

/**
 * An exception class encapsulating all Capstone errors.
 */
class CapstoneError : public BaseError
{
	public:
		CapstoneError(cs_err e);

		std::string getMessage() const;
		virtual const char* what() const noexcept override;

	private:
		/// Capstone error.
		cs_err _csError = CS_ERR_OK;
};

/**
 * An exception class related to Capstone mode setting errors.
 */
class ModeSettingError : public BaseError
{
	public:
		enum class eType
		{
			UNDEF,
			/// Basic mode cannot be used with this arch.
			BASIC_MODE,
			/// Extra mode cannot be used with this arch.
			EXTRA_MODE,
			/// Translator cannnot change basic mode for this architecture.
			BASIC_MODE_CHANGE
		};

	public:
		ModeSettingError(cs_arch a, cs_mode m, eType t);

		std::string getMessage() const;
		virtual const char* what() const noexcept override;

	private:
		cs_arch _arch = CS_ARCH_ALL;
		cs_mode _mode = CS_MODE_LITTLE_ENDIAN;
		eType _type = eType::UNDEF;
};

/**
 * An exception class thrown when unexpected operand(s) (number, type, etc.)
 * is(are) encountered.
 *
 * These exceptions may be suppressed and/or ignored.
 */
class UnexpectedOperandsError : public BaseError
{
	public:
		/**
		 * @param i       Capstone instruction in which unexpected operand
		 *                was encountered.
		 * @param comment Optional comment about the problem.
		 */
		UnexpectedOperandsError(cs_insn* i, const std::string& comment = "");

		virtual const char* what() const noexcept override;

	private:
		cs_insn* _insn = nullptr;
		std::string _comment;
};

/**
 * An exception class thrown when unhandled instruction is encountered.
 *
 * These exceptions may be suppressed and/or ignored. Not all instructions are
 * handled, or will be handled in the future.
 */
class UnhandledInstructionError : public BaseError
{
	public:
		/**
		 * @param i       Capstone instruction which is not handled.
		 * @param comment Optional comment about the problem.
		 */
		UnhandledInstructionError(cs_insn* i, const std::string& comment = "");

		virtual const char* what() const noexcept override;

	private:
		cs_insn* _insn = nullptr;
		std::string _comment;
};

/**
 * A generic exception class for miscellaneous Capstone2LlvmIr errors.
 *
 * These exceptions signal some operational problems in Capstone2LlvmIr library.
 * They should not be ignored. They should be reported to RetDec developers.
 */
class GenericError : public BaseError
{
	public:
		GenericError(const std::string& message);

		virtual const char* what() const noexcept override;

	private:
		/// Message returned by @c what() method.
		std::string _whatMessage;
};

} // namespace capstone2llvmir

#endif
