/**
 * @file include/capstone2llvmir/llvmir_utils.h
 * @brief 工具类：LLVM IR 
 *
 * LLVM IR 工具类：
 * - 与翻译本身无关。
 * - 不要使用翻译类中的任何数据。
 */

#ifndef CAPSTONE2LLVMIR_LLVMIR_UTILS_H
#define CAPSTONE2LLVMIR_LLVMIR_UTILS_H

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>


namespace capstone2llvmir {

/**
 * @return Negation of value @p val.
 */
llvm::Value* generateValueNegate(llvm::IRBuilder<>& irb, llvm::Value* val);

llvm::IntegerType* getIntegerTypeFromByteSize(llvm::Module* module, unsigned sz);

llvm::Type* getFloatTypeFromByteSize(llvm::Module* module, unsigned sz);

/**
 * @brief 在`irb`构建器的当前插入点生成`if-then`语句。
 * ```
    if (cond) {
	  // body
	}
	// after
 * ```
 * @param cond 在`if()`语句中用作条件的值。
 * @param irb  参考`IRBuilder`：生成`if-then`后，`irb`的插入点设置为语句后的第一个指令。
 * @return `IRbuilder`：插入点被设置为`if-then body`基本块的终结器指令。用这个构造器来填充`body`。
 */
llvm::IRBuilder<> generateIfThen(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb);

/**
 * @brief 与`generateIfThen()`相同，但如果`cond`是`true`，则跳过`body`：
 * ```
	if (!cond) {
	  // body
	}
	// after
 * ```
 */
llvm::IRBuilder<> generateIfNotThen(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb);

/**
 * @brief 在`irb`构建器的当前插入点生成`if-then-else`语句。
 * ```
	if (cond) {
	  // bodyIf
	} else {
	  // bodyElse
	}
	// after
 * ```
 * @param cond 在`if()`语句中用作条件的值。
 * @param irb  参考`IRBuilder`：生成`if-then-else`后，`irb`的插入点设置为语句后的第一个指令。
 * @return 一对IR构建器，其插入点设置为`if-then-else`的`bodyIf`（第一个块）和`bodyElse`（第二个块）终止器指令。使用这些构建器来填充`body`。
 */
std::pair<llvm::IRBuilder<>, llvm::IRBuilder<>> generateIfThenElse(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb);

/**
 * @brief 在`irb`构建器的当前插入点生成`while`语句。
 * ```
	// before
	while (cond) {
	  // body
	}
	// after
 * ```
 * @param branch 引用一个分支指令指针，该指针将填充`while`的条件分支，其条件设置为`true`（无限循环）。在IR构建器之前使用来生成条件和`llvm::BranchInst::setCondition()`将其设置为whis分支。
 * @param irb  参考`IRBuilder`：生成`if-then-else`后，`irb`的插入点设置为语句后的第一个指令。
 * @return 一对IR构建器，其插入点设置为BB和循环体BB的终止器指令之前。使用这些构建器来填充`body`。
 */
std::pair<llvm::IRBuilder<>, llvm::IRBuilder<>> generateWhile(
		llvm::BranchInst*& branch,
		llvm::IRBuilder<>& irb);

} // namespace capstone2llvmir

#endif
