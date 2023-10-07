/**
 * \file include/capstone2llvmir/capstone2llvmir.h
 * \brief 翻译器将字节转换为 LLVM IR 的通用公共接口
 */

#ifndef CAPSTONE2LLVMIR_H
#define CAPSTONE2LLVMIR_H

#include <list>
#include <cassert>
#include <memory>

#include <capstone/capstone.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

// 本地库
#include "common/address.h"

#include "capstone2llvmir/exceptions.h"

// 本地子库
#include "capstone2llvmir/arm/arm_defs.h"
#include "capstone2llvmir/arm64/arm64_defs.h"
#include "capstone2llvmir/mips/mips_defs.h"
#include "capstone2llvmir/powerpc/powerpc_defs.h"
#include "capstone2llvmir/x86/x86_defs.h"


namespace capstone2llvmir {

/**
 * 适用于所有翻译器的抽象公共接口类：
 * 翻译器接受 LLVM 模块中的二进制数据和位置，
 * 将数据反汇编为 Capstone 指令，
 * 并翻译这些指令为 LLVM IR 到给定位置。
 */
class Capstone2LlvmIrTranslator
{
//
//==============================================================================
// 命名构造函数
//==============================================================================
//
	public:
		/**
		 * @brief 初始化 capstone 引擎，为编译器创建指定信息
         * @param a: 体系架构
         * @param m: llvm 模块
		 * @param basic: 架构基本硬件模式，对应于硬件（例如：CS_MODE_ARM 或 CS_MODE_THUMB 对应 CS_ARCH_ARM架构）
		 * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArch(
				cs_arch a,
				llvm::Module* m,
				cs_mode basic = CS_MODE_LITTLE_ENDIAN,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
         * @brief 创建32位ARM翻译器（使用基本模式 CS_MODE_ARM），如果您想创建拇指翻译器使用 `createThumb()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArm(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
         * @brief 创建32位ARM转换器（使用基本模式 CS_MODE_THUMB）
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createThumb(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建64位ARM转换器（使用基本模式 CS_MODE_ARM）
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArm64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 MIPS32 位翻译器，以及额外的（使用基本模式 CS_MODE_MIPS32），如果您想创建不同类型的MIPS翻译器，请使用 `createMips64()`、`createMips3()`或`createMips32R6()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 MIPS64 位翻译器，以及额外的（使用基本模式 CS_MODE_MIPS64），如果您想创建不同类型的MIPS翻译器，请使用 `createMips32()`、`createMips3()`或`createMips32R6()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 MIPS3 翻译器，以及额外的（使用基本模式 CS_MODE_MIPS3），如果您想创建不同类型的MIPS翻译器，请使用 `createMips64()`、`createMips32()`或`createMips32R6()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips3(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 MIPS32R6 翻译器，以及额外的（使用基本模式 CS_MODE_MIPS32R6），如果您想创建不同类型的MIPS翻译器，请使用 `createMips64()`、`createMips3()`或`createMips32()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips32R6(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 x86 16位翻译器（使用基本模式 CS_MODE_16），如果您想创建不同类型的 x86 翻译器，请使用 `createX86_32()` 或 `createX86_64()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_16(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 x86 32位翻译器（使用基本模式 CS_MODE_32），如果您想创建不同类型的 x86 翻译器，请使用 `createX86_16()` 或 `createX86_64()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 x86 64位翻译器（使用基本模式 CS_MODE_64），如果您想创建不同类型的 x86 翻译器，请使用 `createX86_16()` 或 `createX86_32()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建32位 PowerPC 翻译器（使用基本模式 CS_MODE_32），如果您想创建64位PowerPC转换器，请使用 `createPpc64()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpc32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建64位 PowerPC 翻译器（使用基本模式 CS_MODE_64），如果您想创建32位PowerPC转换器，请使用 `createPpc64()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpc64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
         * @brief 创建QPX PowerPC转换器（使用基本模式 CS_MODE_QPX），如果您想创建32位 PowerPC 翻译器使用 `createPpc32()`。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpcQpx(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建SPARC翻译器。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createSparc(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 Systemz 翻译器。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createSysz(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * @brief 创建 Xcore 翻译器。
         * @param m: llvm 模块
         * @param extra: 架构额外的模式可以与基本的硬件模式相结合（例如：CS_MODE_BIG_ENDIAN）
		 * @return 返回翻译器的 unique_ptr ，假如无法创建（具有指定模式）的翻译器，则返回 nullptr。
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createXcore(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);

		virtual ~Capstone2LlvmIrTranslator() = default;
//
//==============================================================================
// 翻译器配置方法
//==============================================================================
//
		/**
		 * @brief 翻译器是否应该忽略在Capstone指令中遇到的意外操作数？
		 * @return `True`（默认）->忽略->尝试恢复或忽略问题； 
		 * @return `False`->不要忽略->抛出`UnexpectedOperandsError`
		 */
		virtual void setIgnoreUnexpectedOperands(bool f) = 0;
		/**
		 * @brief 翻译器应该忽略未处理的指令吗？
		 * @return `True`（默认）->忽略->尝试恢复或忽略问题； 
		 * @return `False`->不要忽略->抛出`UnhandledInstructionError`
		 */
		virtual void setIgnoreUnhandledInstructions(bool f) = 0;
		/**
		 * @brief 翻译器是否应该为未实现完整语义的指令生成伪汇编函数？
		 * @return `True`（默认）->生成； 
		 * @return `False`->不生成
		 */
		virtual void setGeneratePseudoAsmFunctions(bool f) = 0;

		virtual bool isIgnoreUnexpectedOperands() const = 0;
		virtual bool isIgnoreUnhandledInstructions() const = 0;
		virtual bool isGeneratePseudoAsmFunctions() const = 0;
//
//==============================================================================
// 模式 `mode` 查询和修改方法
//==============================================================================
//
	public:
		/**
		 * @brief 检查基本模式是否是翻译器允许的基本模式。（这必须在具体的类中实现，因为它是特定于架构和翻译的。）
		 * @param m 模式 `cs_mode`
		 * @return 如果允许模式，则为 `true`，否则为 `false`。
		 */
		virtual bool isAllowedBasicMode(cs_mode m) = 0;
		/**
		 * @brief 检查拓展模式是否是翻译器允许的基本模式。（这必须在具体的类中实现，因为它是特定于架构和翻译的。）
		 * @param m 模式 `cs_mode`
		 * @return 如果允许模式，则为 `true`，否则为 `false`。
		 */
		virtual bool isAllowedExtraMode(cs_mode m) = 0;
		/**
		 * @brief 修改基本模式（例如 CS_MODE_ARM 到 CS_MODE_THUMB ）。 
         * 这必须在具体类中实现，这样才能检查请求的模式是否适用。
         * 并非每个基本模式都可以用于每个架构。
         * 某些架构的翻译器（例如CS_ARCH_X86）由于内部问题，甚至可能不允许在Capstone允许的模式之间切换
         * （例如，16/32/64 x86架构之间的不同寄存器环境）
		 */
		virtual void modifyBasicMode(cs_mode m) = 0;
		/**
		 * 修改额外模式（例如 CS_MODE_LITTLE_ENDIAN 到 CS_MODE_BIG_ENDIAN ）。
		 * 这必须在具体类中实现，这样才能检查请求的模式是否适用。
		 * 并非每个基本模式都可以用于每个架构。
		 */
		virtual void modifyExtraMode(cs_mode m) = 0;

		/**
		 * @return 根据当前设置的基本架构字节大小模式。
		 */
		virtual uint32_t getArchByteSize() = 0;
		/**
		 * @return 根据当前设置的基本架构位大小模式。
		 */
		virtual uint32_t getArchBitSize() = 0;
//
//==============================================================================
// 翻译方法
//==============================================================================
//
	public:
		/// @brief 翻译结果数据：<LLVM IR, Capstone>指令对，字节大小，指令数，条件分支
		struct TranslationResult
		{
			bool failed() const { return size == 0; }

			/// 指令翻译映射的列表 <LLVM IR, Capstone>：
			/// 前者：LLVM IR 指令
			/// 后者：Capstone 指令.
			/// 所有创建的 LLVM IR 指令都添加到工作 LLVM 模块中，并在模块销毁时自动销毁。
			/// 所有 Capstone 指令都通过此方法动态分配，并且必须由调用者释放，以避免内存泄漏。
			std::list<std::pair<llvm::StoreInst*, cs_insn*>> insns;
			/// 翻译的二进制块的字节大小
			std::size_t size = 0;
			/// 翻译的汇编指令的数量
			std::size_t count = 0;
			/// 如果设置了 `stopOnBranch` ，则设置为终止分支指令（遇到任何类型，即调用、返回、分支、cond分支后终止）；如果没有此类指令，则设置为 `nullptr`。
			llvm::CallInst* branchCall = nullptr;
			/// 如果 `branchCall` 在条件代码中，则为真，例如，if-then中的无条件分支。
			bool inCondition = false;
		};
		/**
		 * 翻译给定的字节
		 * @param bytes 要翻译的字节。
		 * @param size  字节缓冲区的大小。
		 * @param a     字节所在的内存地址。
		 * @param irb   LLVM IR构建器：用于创建LLVM IR翻译，翻译的LLVM IR指令在其当前位置。
		 * @param count 要翻译的组装指令数量，或设置为0全部翻译。
		 * @param stopOnBranch 如果设置，翻译将在遇到任何类型的分支（调用、返回、分支、条件分支）后中止。
		 * @return 请参阅 `TranslationResult` 结构。
		 */
		virtual TranslationResult translate(
				const uint8_t* bytes,
				std::size_t size,
				common::Address a,
				llvm::IRBuilder<>& irb,
				std::size_t count = 0,
				bool stopOnBranch = false) = 0;

		/// @brief 翻译结果数据（一条）：<LLVM IR, Capstone>指令对，字节大小，指令数，条件分支 
		struct TranslationResultOne
		{
			bool failed() const { return size == 0; }

			/// 翻译的用于 LLVM IR <-> Capstone 指令映射的特殊LLVM IR指令。
			/// 所有创建的 LLVM IR 指令都添加到工作 LLVM 模块中，并在模块销毁时自动销毁。
			llvm::StoreInst* llvmInsn = nullptr;
			/// 翻译的 Capstone 指令
			/// Capstone指令由此方法动态分配，必须由调用者释放，以避免内存泄漏
			cs_insn* capstoneInsn = nullptr;
			/// 翻译的二进制块的字节大小。
			std::size_t size = 0;
			/// 如果设置了`stopOnBranch`，则设置为终止分支指令（任何类型，即调用、返回、分支、cond分支），如果没有此类指令，则设置为`nullptr`。
			llvm::CallInst* branchCall = nullptr;
			/// 如果`branchCall`在条件代码中，则为真，例如，if-then中的无条件分支。
			bool inCondition = false;
		};
		/**
		 * 从给定的字节中翻译一个程序集指令。
		 * @param bytes 要翻译的字节。
		 * @param size  字节缓冲区的大小。
		 * @param a     字节所在的内存地址。
		 * @param irb   LLVM IR构建器：用于创建LLVM IR翻译，翻译的LLVM IR指令在其当前位置。
		 * @return 请参阅 `TranslationResultOne` 结构。
		 */
		virtual TranslationResultOne translateOne(
				const uint8_t*& bytes,
				std::size_t& size,
				common::Address& a,
				llvm::IRBuilder<>& irb) = 0;
//
//==============================================================================
// Capstone相关的获取器和查询方法
//==============================================================================
//
	public:
		/**
		 * @return 返回Capstone引擎句柄.
		 */
		virtual const csh& getCapstoneEngine() const = 0;
		/**
		 * @return 此翻译器初始化的 Capstone 体系架构。
		 */
		virtual cs_arch getArchitecture() const = 0;
		/**
		 * @return 此翻译器目前处于 Capstone 基本模式。
		 */
		virtual cs_mode getBasicMode() const = 0;
		/**
		 * @return 此翻译器目前处于 Capstone 额外模式。
		 */
		virtual cs_mode getExtraMode() const = 0;

		/**
		 * 指定的Capstone指令`id`是否有任何类型的延迟插槽？
		 */
		virtual bool hasDelaySlot(uint32_t id) const = 0;
		/**
		 * 是否有指定的Capstone指令`id`典型的延迟插槽？
		 */
		virtual bool hasDelaySlotTypical(uint32_t id) const = 0;
		/**
		 * 指定的 Capstone 指令`id`是否可能延迟插槽？
		 */
		virtual bool hasDelaySlotLikely(uint32_t id) const = 0;
		/**
		 * @return 指定 Capstone 指令`id`的延迟插槽的大小（指令数量）。
		 */
		virtual std::size_t getDelaySlot(uint32_t id) const = 0;

		/**
		 * @return 对应于指定 Capstone 的 LLVM 全局变量寄存器`r`，如果这种全局寄存器不存在，则返回`nullptr`。
		 */
		virtual llvm::GlobalVariable* getRegister(uint32_t r) = 0;
		/**
		 * @return Register name corresponding to the specified Capstone
		 * register @p r. The name may differ from names used by the Capstone
		 * library. This function works even for the additional registers
		 * defined in translators and missing in Capstone (e.g. individual flag
		 * registers).
		 * Throws @c Capstone2LlvmIrError exception if register name not found.
		 */
		virtual std::string getRegisterName(uint32_t r) const = 0;
		/**
		 * @return 寄存器位大小对应于指定的Capstone寄存器 `r`。
         * 此功能甚至适用于翻译器中定义和Capstone中缺失的附加寄存器（例如单个标志寄存器）。
		 * 如果找不到寄存器位大小，则抛出`Capstone2LlvmIrError`异常。
		 */
		virtual uint32_t getRegisterBitSize(uint32_t r) const = 0;
		/**
		 * @return 寄存器字节大小对应于指定的Capstone寄存器`r`。此功能甚至适用于翻译器中定义和Capstone中缺失的附加寄存器（例如单个标志寄存器）。
		 * 如果找不到寄存器字节大小，则抛出`Capstone2LlvmIrError`异常。
		 */
		virtual uint32_t getRegisterByteSize(uint32_t r) const = 0;
		/**
		 * @return 寄存器数据类型对应于指定的Capstone寄存器`r`。此功能甚至适用于翻译器中定义和Capstone中缺失的附加寄存器（例如单个标志寄存器）。
		 * 如果找不到寄存器数据类型，则抛出`Capstone2LlvmIrError`异常。
		 */
		virtual llvm::Type* getRegisterType(uint32_t r) const = 0;

		/**
         * @brief 检查此指令的转换是否会/可能产生任何类型的控制流更改伪调用（即call/return/br/condbr伪函数调用）。
		 * 对于ARM，参数`i`必须包含详细成员 - 指令不能用如下反汇编：
         * CS_OP_DETAIL = CS_OPT_ON 或者用 CS_OP_SKIPDATA = CS_OPT_ON.
		 *
		 * 对于x86，MIPS，PowerPC，参数`i`可能不包括详细信息成员 - 指令可以用如下反汇编：
		 * CS_OP_DETAIL = CS_OPT_ON 或者用 CS_OP_SKIPDATA = CS_OPT_ON.
		 *
		 * 在没有实际翻译指令的情况下找到这些信息有时很棘手。
         * 另一方面，对于某些架构，可以提供更详细的信息。
		 * （例如，伪函数调用的类型），有时甚至仅从指令ID（即 `cs_insn::id`）：
		 * - x86: 仅从指令ID就可以识别各种伪函数调用。
		 * - mips: 仅从指令ID就可以识别各种伪函数调用。
		 * - powerpc: 可以确定指令是否仅从指令ID更改控制流。 很难/不可能在没有细节的情况下确定类型，并复制翻译中使用的完整分析。
		 * - arm: 无法确定指令是否仅从指令ID更改控制流。指令可以直接编写程序计数器 - 需要指令细节。指令可能是有条件的。
		 */
		virtual bool isControlFlowInstruction(cs_insn& i) const = 0;
		/**
		 * @return 如果Capstone指令`i`是任何类型的调用指令，则为真，其翻译将产生调用伪调用。否则是假的。
		 * @note 这可能并不总是为所有架构所熟知。目前，它仅适用于x86和MIPS。有关更多详细信息，请参阅`isControlFlowInstruction()`。
		 */
		virtual bool isCallInstruction(cs_insn& i) const = 0;
		/**
		 * @return 如果Capstone指令`i`是任何类型的返回指令，则为`true`，其翻译将产生返回伪调用。否则`false`。
		 * @note 这可能并不总是为所有架构所熟知。目前，它仅适用于x86和MIPS。有关更多详细信息，请参阅`isControlFlowInstruction()`。
		 */
		virtual bool isReturnInstruction(cs_insn& i) const = 0;
		/**
		 * @return 如果Capstone指令 `i`是任何类型的分支指令，则为`true`，其翻译将产生分支伪调用。否则`false`。
		 * @note 这可能并不总是为所有架构所熟知。目前，它仅适用于x86和MIPS。有关更多详细信息，请参阅`isControlFlowInstruction()`。
		 */
		virtual bool isBranchInstruction(cs_insn& i) const = 0;
		/**
		 * @return 如果Capstone指令 `i`是任何类型的条件分支指令，则为`true`，其翻译将产生条件分支伪调用。否则 `false`。
		 * @note 这可能并不总是为所有架构所熟知。目前，它仅适用于x86和MIPS。有关更多详细信息，请参阅`isControlFlowInstruction()`。
		 */
		virtual bool isCondBranchInstruction(cs_insn& i) const = 0;
//
//==============================================================================
// LLVM相关的获取器和查询方法
//==============================================================================
//
	public:
		/**
		 * @return 此翻译器使用的LLVM模块
		 */
		virtual llvm::Module* getModule() const = 0;

		/**
		 * Is the passed LLVM value @p v the special global variable used for
		 * LLVM IR <-> Capstone instruction mapping?
		 */
		virtual bool isSpecialAsm2LlvmMapGlobal(llvm::Value* v) const = 0;
		/**
		 * Is the passed LLVM value @p v a special instruction used for
		 * LLVM IR <-> Capstone instruction mapping?
		 * @return Value @p v casted to @c llvm::StoreInst if it is a special
		 * mapping instruction, @c nullptr otherwise.
		 */
		virtual llvm::StoreInst* isSpecialAsm2LlvmInstr(llvm::Value* v) const = 0;
		/**
		 * @return LLVM global variable used for LLVM IR <-> Capstone
		 * instruction mapping?
		 */
		virtual llvm::GlobalVariable* getAsm2LlvmMapGlobalVariable() const = 0;

		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents call operation in the translated LLVM IR?
		 */
		virtual bool isCallFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a call operation in the translated LLVM IR?
		 */
		virtual bool isCallFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Is @c isCallFunctionCall() @c true for the passed LLVM call
		 * instruction @p c, and execution of the call instruction @p c is
		 * conditional.
		 * @return Branch instruction which true branch jumps to the @p c if
		 *         @p c is conditional, @c nullptr otherwise.
		 */
		virtual llvm::BranchInst* isInConditionCallFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call
		 * represents a call operation in the translated LLVM IR.
		 * Function signature: @code{.cpp} void (i<arch_sz>) @endcode
		 */
		virtual llvm::Function* getCallFunction() const = 0;
		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents return operation in the translated LLVM IR?
		 */
		virtual bool isReturnFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a return operation in the translated
		 * LLVM IR?
		 */
		virtual bool isReturnFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Is @c isReturnFunctionCall() @c true for the passed LLVM call
		 * instruction @p c, and execution of the call instruction @p c is
		 * conditional.
		 * @return Branch instruction which true branch jumps to the @p c if
		 *         @p c is conditional, @c nullptr otherwise.
		 */
		virtual llvm::BranchInst* isInConditionReturnFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call
		 * represents a return operation in the translated LLVM IR.
		 * Function signature: @code{.cpp} void (i<arch_sz>) @endcode
		 */
		virtual llvm::Function* getReturnFunction() const = 0;
		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents branch operation in the translated LLVM IR?
		 */
		virtual bool isBranchFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a branch operation in the translated
		 * LLVM IR?
		 */
		virtual bool isBranchFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Is @c isBranchFunctionCall() @c true for the passed LLVM call
		 * instruction @p c, and execution of the call instruction @p c is
		 * conditional.
		 * @return Branch instruction which true branch jumps to the @p c if
		 *         @p c is conditional, @c nullptr otherwise.
		 */
		virtual llvm::BranchInst* isInConditionBranchFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call
		 * represents a branch operation in the translated LLVM IR.
		 * Function signature: @code{.cpp} void (i<arch_sz>) @endcode
		 */
		virtual llvm::Function* getBranchFunction() const = 0;
		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents conditional branch operation in the translated
		 * LLVM IR?
		 * Function signature: @code{.cpp} void (i1, i<arch_sz>) @endcode
		 */
		virtual bool isCondBranchFunction(llvm::Function* f) const = 0;
		/**
		 * Is @c isCondBranchFunction() @c true for the passed LLVM call
		 * instruction @p c, and execution of the call instruction @p c is
		 * conditional.
		 * @return Branch instruction which true branch jumps to the @p c if
		 *         @p c is conditional, @c nullptr otherwise.
		 */
		virtual llvm::BranchInst* isInConditionCondBranchFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a conditional branch operation in the
		 * translated LLVM IR?
		 */
		virtual bool isCondBranchFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call
		 * represents a conditional branch operation in the translated LLVM IR.
		 */
		virtual llvm::Function* getCondBranchFunction() const = 0;

		/**
		 * Is the passed LLVM function @p f any kind of pseudo function
		 * generated by capstone2llvmir (e.g. call/return/br/... function).
		 */
		virtual bool isAnyPseudoFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call @p c any kind of pseudo call generated by
		 * capstone2llvmir (e.g. call/return/br/... function call).
		 */
		virtual bool isAnyPseudoFunctionCall(llvm::CallInst* c) const = 0;

		/**
		 * Is the passed LLVM value @p v a global variable representing some
		 * HW register?
		 * @return Value @p v casted to @c llvm::GlobalVariable if it is
		 * representing some HW register, @c nullptr otherwise.
		 */
		virtual llvm::GlobalVariable* isRegister(llvm::Value* v) const = 0;
		/**
		 * @return Capstone register corresponding to the provided LLVM global
		 * variable @p gv if such register exists, zero otherwise (zero equals
		 * to @c [arch]_REG_INVALID in all Capstone architecture models, e.g.
		 * @c ARM_REG_INVALID, @c MIPS_REG_INVALID).
		 */
		virtual uint32_t getCapstoneRegister(llvm::GlobalVariable* gv) const = 0;

		/**
		 * Is the passed LLVM function @p f any pseudo assembly functions for
		 * instructions which full semantics is not implemented?
		 */
		virtual bool isPseudoAsmFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call @p c any kind of pseudo assembly call for
		 * instructions which full semantics is not implemented?
		 */
		virtual bool isPseudoAsmFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Get all pseudo assembly functions for instructions which full
		 * semantics is not implemented.
		 */
		virtual const std::set<llvm::Function*>& getPseudoAsmFunctions() const = 0;
};

} // namespace capstone2llvmir

#endif
