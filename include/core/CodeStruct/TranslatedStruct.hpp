/// \file include/core/CodeStruct/Translated.hpp
/// \brief 翻译块结构体定义

#ifndef TRANSLATEDBLOCK_HPP
#define TRANSLATEDBLOCK_HPP

#include "BasicStruct.hpp"


namespace TranslationStruct {

using TB = TranslationBlock ;
using TRO = TranslationResultOne;

/// @brief 翻译块
class TranslationBlock {
private:
    /* data */
public:
    /// 翻译的二进制块的字节大小
    std::size_t size = 0;
    /// 如果设置了 `stopOnBranch` ，则设置为终止分支指令（遇到任何类型，即调用、返回、分支、cond分支后终止）；如果没有此类指令，则设置为 `nullptr`。
    llvm::CallInst *branchCall = nullptr;
    /// 如果 `branchCall` 在条件代码中，则为真，例如，if-then中的无条件分支。
    bool inCondition = false;

    TranslationBlock();

    /**
     * @brief `TB`构造函数：翻译给定的字节，并封装为翻译块
     * @param bytes TB要翻译的字节。
     * @param size  字节缓冲区的大小。
     * @param address 字节所在的内存地址。
     * @param irb   LLVM IR构建器：用于创建LLVM IR翻译，翻译的LLVM IR指令在其当前位置。
     * @param count 要翻译的组装指令数量，或设置为0全部翻译。
     * @param stopOnBranch 如果设置，翻译将在遇到任何类型的分支（调用、返回、分支、条件分支）后中止。
     * @return `TranslationBlock` 翻译块
     */
    TranslationBlock(const uint8_t *bytes,
                    std::size_t size,
                    uint64_t address,
                    llvm::IRBuilder<> &irb,
                    std::size_t count = 0,
                    bool stopOnBranch = false);

    /**
     * @brief `TB`构造函数：翻译给定的字节，并封装为翻译块
     * @param bytes TB要翻译的字节。
     * @param size  字节缓冲区的大小。
     * @param address 字节所在的内存地址。
     * @param bb    待翻译基本块
     * @param irb   LLVM IR构建器：用于创建LLVM IR翻译，翻译的LLVM IR指令在其当前位置。
     * @param stopOnBranch 如果设置，翻译将在遇到任何类型的分支（调用、返回、分支、条件分支）后中止。
     * @return `TranslationBlock` 翻译块
     */
    TranslationBlock(const uint8_t *bytes,
                    std::size_t size,
                    uint64_t address,
                    BasicStruct::BB bb,
                    llvm::IRBuilder<> &irb,
                    bool stopOnBranch = false);

    ~TranslationBlock();

    bool failed() const { return size == 0; }
};

/// @brief 翻译块（一条指令）
class TranslationResultOne
{
public:
    /// 翻译的用于 LLVM IR <-> Capstone 指令映射的特殊LLVM IR指令。
    /// 所有创建的 LLVM IR 指令都添加到工作 LLVM 模块中，并在模块销毁时自动销毁。
    llvm::StoreInst *llvmInsn = nullptr;
    /// 翻译的 Capstone 指令
    /// Capstone指令由此方法动态分配，必须由调用者释放，以避免内存泄漏
    cs_insn *capstoneInsn = nullptr;
    /// 翻译的二进制块的字节大小。
    std::size_t size = 0;
    /// 如果设置了`stopOnBranch`，则设置为终止分支指令（任何类型，即调用、返回、分支、cond分支），如果没有此类指令，则设置为`nullptr`。
    llvm::CallInst *branchCall = nullptr;
    /// 如果`branchCall`在条件代码中，则为真，例如，if-then中的无条件分支。
    bool inCondition = false;

    bool failed() const { return size == 0; }

    TranslationResultOne();

    ~TranslationResultOne();
};

}


#endif // TRANSLATEDBLOCK_HPP
