/**
 * @file include/common/type.h
 * @brief 通用数据类型表示
 */

#ifndef COMMON_TYPE_H
#define COMMON_TYPE_H

#include <set>
#include <string>


namespace common {

/**
 * 表示数据类型。
 *
 * 类型的LLVM IR表示是其唯一的ID。
 */
class Type
{
	public:
		Type();
		Type(const std::string& llvmIrRepre);

		/// @name 类型查询方法
		/// @{
		bool isDefined() const;
		bool isWideString() const;
		/// @}

		/// @name 类型设置方法
		/// @{
		void setLlvmIr(const std::string& t);
		void setIsWideString(bool b);
		/// @}

		/// @name 类型获取方法
		/// @{
		std::string getId() const;
		std::string getLlvmIr() const;
		/// @}

		bool operator<(const Type& val) const;
		bool operator==(const Type& val) const;

	private:
		/// LLVM IR字符串表示。
		/// 唯一ID。
		std::string _llvmIr = "i32";
		/// 宽字符串在LLVM IR中表示为int数组
		/// 此标志可用于将它们与普通int数组区分开来
		bool _wideString = false;
};

using TypeContainer = std::set<Type>;

} // namespace common

#endif
