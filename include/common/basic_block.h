/**
 * @file include/common/basic_block.h
 * @brief 通用的基本块表示。
 */

#ifndef COMMON_BASIC_BLOCK_H
#define COMMON_BASIC_BLOCK_H

#include <set>
#include <tuple>

#include "common/address.h"
#include "common/range.h"

struct cs_insn;


namespace common {

class BasicBlock : public AddressRange
{
	public:
		using AddressRange::AddressRange;

	public:
		/// 前身基本块的起始地址。
		std::set<Address> preds;
		/// 后续基本块的起始地址。
		std::set<Address> succs;

		/// 这个基本块中的所有调用
		struct CallEntry
		{
			Address srcAddr;
			Address targetAddr;

			bool operator<(const CallEntry& o) const
			{
				return std::tie(srcAddr, targetAddr)
						< std::tie(o.srcAddr, o.targetAddr);
			}
		};
		std::set<CallEntry> calls;

		/// 基本块说明
		/// These are pointers to Capstone instruction representations.
		/// Fill this member only if it is needed.
		/// If used, the user of this library needs to include Capstone header
		/// and link Capstone library. This library does neither.
		std::vector<cs_insn*> instructions;
};

} // namespace common


#endif
