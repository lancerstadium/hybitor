/// \file include/core/CodeStruct/BasicBlock.hpp
/// \brief 基本块结构体定义

#ifndef BASICBLOCK_HPP
#define BASICBLOCK_HPP

#include <set>
#include <vector>
#include <string>
#include <list>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <capstone/capstone.h>

#include <capstone/capstone.h>


namespace BasicStruct {

typedef BasicBlock BB;

/// @brief 基本块结构体
class BasicBlock
{
private:

public:
    uint64_t start_address;                     // 基本块的起始地址
    std::set<uint64_t> pred_BB_addresses;       // 前驱基本块的入口地址
    std::set<uint64_t> succ_BB_addresses;       // 后继基本块的入口地址
    
	std::size_t count = 0;  // 要翻译的汇编指令的数量
    
    /// 包含的指令列表
    /// 指令翻译映射的列表 <LLVM IR, Capstone>：
	/// 前者：LLVM IR 指令
	/// 后者：Capstone 指令.
	/// 所有创建的 LLVM IR 指令都添加到工作 LLVM 模块中，并在模块销毁时自动销毁。
	/// 所有 Capstone 指令都通过此方法动态分配，并且必须由调用者释放，以避免内存泄漏
    std::list<std::pair<llvm::StoreInst*, cs_insn*>> insns; 

// ------------- BasicBlock 构造&析构操作区 ------------- //

    BasicBlock(uint64_t BB_start_address) : start_address(BB_start_address) {}
    ~BasicBlock() {}

};

}





#endif // BASICBLOCK_HPP