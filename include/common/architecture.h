/**
 * @file include/common/architecture.h
 * @brief 共同的架构表示。
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef COMMON_ARCHITECTURE_H
#define COMMON_ARCHITECTURE_H

#include <string>

namespace common {

/**
 * 表示输入二进制的目标架构。
 */
class Architecture
{
	public:
		/// @name 架构查询方法。
		/// @{
		bool isUnknown() const;
		bool isKnown() const;
		bool isMips() const;
		bool isMips64() const;
		bool isPic32() const;
		bool isMipsOrPic32() const;
		bool isArm() const;
		bool isArm32() const;
		bool isArm64() const;
		bool isThumb() const;
		bool isArm32OrThumb() const;
		bool isX86() const;
		bool isX86_16() const;
		bool isX86_32() const;
		bool isX86_64() const;
		bool isPpc() const;
		bool isPpc64() const;
		bool isEndianLittle() const;
		bool isEndianBig() const;
		bool isEndianKnown() const;
		bool isEndianUnknown() const;
		/// @}

		/// @name 架构设置方法。
		/// @{
		void setIsUnknown();
		void setIsMips();
		void setIsPic32();
		void setIsArm();
		void setIsThumb();
		void setIsArm32();
		void setIsArm64();
		void setIsX86();
		void setIsPpc();
		void setIsEndianLittle();
		void setIsEndianBig();
		void setIsEndianUnknown();
		void setName(const std::string &n);
		void setBitSize(unsigned bs);
		/// @}

		/// @name 架构获取方法。
		/// @{
		std::string getName() const;
		unsigned getBitSize() const;
		unsigned getByteSize() const;
		/// @}

	private:
		enum eEndian
		{
			E_UNKNOWN,
			E_LITTLE,
			E_BIG
		};

		enum class eArch
		{
			UNKNOWN,
			MIPS,
			PIC32,
			ARM,
			X86,
			PPC,
		};

	private:
		bool isArch(const std::string& a) const;
		bool isArch(eArch a) const;
		void setArch();

	private:
		std::string _name;
		unsigned _bitSize = 32;
		bool _thumbFlag = false;
		eEndian _endian = E_UNKNOWN;
		eArch _arch = eArch::UNKNOWN;
};

} // namespace common

#endif
