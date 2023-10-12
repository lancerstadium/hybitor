/**
 * @file include/capstone2llvmir/capstone_utils.h
 * @brief 工具类：在Capstone中定义的类型、体系结构的映射表
 */

#ifndef CAPSTONE2LLVMIR_CAPSTONE_UTILS_H
#define CAPSTONE2LLVMIR_CAPSTONE_UTILS_H

#include <map>
#include <string>

#include <capstone/capstone.h>


namespace capstone2llvmir {

/// @brief Capstone体系结构类型与其对应字符串的映射表
static std::map<cs_arch, std::string> capstoneArchStringMap =
{
		{CS_ARCH_ARM, "CS_ARCH_ARM"},
		{CS_ARCH_ARM64, "CS_ARCH_ARM64"},
		{CS_ARCH_MIPS, "CS_ARCH_MIPS"},
		{CS_ARCH_X86, "CS_ARCH_X86"},
		{CS_ARCH_PPC, "CS_ARCH_PPC"},
		{CS_ARCH_SPARC, "CS_ARCH_SPARC"},
		{CS_ARCH_SYSZ, "CS_ARCH_SYSZ"},
		{CS_ARCH_XCORE, "CS_ARCH_XCORE"},
		{CS_ARCH_MAX, "CS_ARCH_MAX"},
		{CS_ARCH_ALL, "CS_ARCH_ALL"}
};

/// @brief 在映射表中寻找Capstone体系结构对应的字符串
/// @param a Capstone 体系结构枚举数
/// @return 对应体系结构字符串
inline std::string capstoneArchToString(cs_arch a)
{
	auto fIt = capstoneArchStringMap.find(a);
	return fIt != capstoneArchStringMap.end() ? fIt->second : std::string();
}

/// @brief Capstone模式类型与其对应字符串的映射表
static std::map<cs_mode, std::string> capstoneModeStringMap =
{
		{CS_MODE_LITTLE_ENDIAN, "CS_MODE_LITTLE_ENDIAN"},
		{CS_MODE_ARM, "CS_MODE_ARM"},
		{CS_MODE_16, "CS_MODE_16"},
		{CS_MODE_32, "CS_MODE_32"},
		{CS_MODE_64, "CS_MODE_64"},
		{CS_MODE_THUMB, "CS_MODE_THUMB"},
		{CS_MODE_MCLASS, "CS_MODE_MCLASS"},
		{CS_MODE_V8, "CS_MODE_V8"},
		{CS_MODE_MICRO, "CS_MODE_MICRO"},
		{CS_MODE_MIPS3, "CS_MODE_MIPS3"},
		{CS_MODE_MIPS32R6, "CS_MODE_MIPS32R6"},
		{CS_MODE_V9, "CS_MODE_V9"},
		{CS_MODE_BIG_ENDIAN, "CS_MODE_BIG_ENDIAN"},
		{CS_MODE_MIPS32, "CS_MODE_MIPS32"},
		{CS_MODE_MIPS64, "CS_MODE_MIPS64"}
};

/// @brief 在映射表中寻找Capstone模式对应的字符串
/// @param m Capstone 模式枚举数
/// @return 对应模式字符串
inline std::string capstoneModeToString(cs_mode m)
{
	auto fIt = capstoneModeStringMap.find(m);
	return fIt != capstoneModeStringMap.end() ? fIt->second : std::string();
}

} // namespace capstone2llvmir

#endif
