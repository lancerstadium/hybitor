/**
 * @file include/retdec/fileformat/types/relocation_table/relocation.h
 * @brief Class for one relocation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RELOCATION_TABLE_RELOCATION_H
#define RETDEC_FILEFORMAT_TYPES_RELOCATION_TABLE_RELOCATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace retdec {
namespace fileformat {

/**
 * One relocation
 */
class Relocation
{
	private:
		std::string name;                       ///< relocation name
		unsigned long long address = 0;         ///< address at which to apply the relocation
		unsigned long long offsetInSection = 0; ///< offset of relocation in section at which to apply the relocation
		unsigned long long linkToSection = 0;   ///< link to section at which relocation is applied
		unsigned long long linkToSymbol = 0;    ///< link to symbol which is used for calculating relocations
		unsigned long long addend = 0;          ///< addend of relocation
		unsigned long long type = 0;            ///< type of relocation
		bool linkToSectionIsValid = false;      ///< @c true if link to section is valid
		bool linkToSymbolIsValid = false;       ///< @c true if link to symbol is valid
		std::vector<std::uint8_t> mask;         ///< relocation mask
	public:
		/// @name Getters
		/// @{
		std::string getName() const;
		unsigned long long getAddress() const;
		unsigned long long  getSectionOffset() const;
		bool getLinkToSection(unsigned long long &sectionIndex) const;
		bool getLinkToSymbol(unsigned long long &symbolIndex) const;
		unsigned long long getAddend() const;
		unsigned long long getType() const;
		std::vector<std::uint8_t> getMask() const;
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string relocationName);
		void setAddress(unsigned long long relocationAddress);
		void setSectionOffset(unsigned long long relocationOffsetInSection);
		void setLinkToSection(unsigned long long relocationLinkToSection);
		void setLinkToSymbol(unsigned long long relocationLinkToSymbol);
		void setAddend(unsigned long long relocationAddend);
		void setType(unsigned long long relocationType);
		void setMask(const std::vector<std::uint8_t> &relocationMask);
		/// @}

		/// @name Other methods
		/// @{
		void invalidateLinkToSection();
		void invalidateLinkToSymbol();
		bool hasEmptyName() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
