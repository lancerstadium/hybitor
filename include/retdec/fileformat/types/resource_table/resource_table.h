/**
 * @file include/retdec/fileformat/types/resource_table/resource_table.h
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_TABLE_H

#include <memory>
#include <utility>
#include <vector>

#include "retdec/fileformat/types/resource_table/resource.h"
#include "retdec/fileformat/types/resource_table/resource_icon_group.h"

namespace retdec {
namespace fileformat {

/**
 * Definition of the icon priority structure
 */

struct IconPriorityEntry
{
	IconPriorityEntry(std::uint16_t width, std::uint16_t bitCount)
	{
		iconWidth = width;
		iconBitCount = bitCount;
	}

	std::uint16_t iconWidth;
	std::uint16_t iconBitCount;
};

/**
 * Table of resources
 */
class ResourceTable
{
	private:
		using resourcesIterator = std::vector<std::unique_ptr<Resource>>::const_iterator;
		std::vector<std::unique_ptr<Resource>> table;                ///< stored resources
		std::vector<Resource *> resourceVersions;             ///< version info resources
		std::vector<ResourceIconGroup *> iconGroups;                 ///< icon groups
		std::vector<ResourceIcon *> icons;                           ///< icons
		std::vector<std::pair<std::string, std::string>> languages;  ///< supported languages, LCID and code page
		std::vector<std::pair<std::string, std::string>> strings;    ///< version info strings
		std::string iconHashCrc32;                                   ///< iconhash CRC32
		std::string iconHashMd5;                                     ///< iconhash MD5
		std::string iconHashSha256;                                  ///< iconhash SHA256
		std::string iconPerceptualAvgHash;                           ///< icon perceptual hash AvgHash

		std::string computePerceptualAvgHash(const ResourceIcon &icon) const;
		bool parseVersionInfo(const std::vector<std::uint8_t> &bytes);
		bool parseVersionInfoChild(const std::vector<std::uint8_t> &bytes, std::size_t &offset);
		bool parseVarFileInfoChild(const std::vector<std::uint8_t> &bytes, std::size_t &offset);
		bool parseStringFileInfoChild(const std::vector<std::uint8_t> &bytes, std::size_t &offset);
		bool parseVarString(const std::vector<std::uint8_t> &bytes, std::size_t &offset);
	public:
		/// @name Getters
		/// @{
		std::size_t getNumberOfResources() const;
		std::size_t getNumberOfLanguages() const;
		std::size_t getNumberOfStrings() const;
		std::size_t getSizeInFile() const;
		std::size_t getLoadedSize() const;
		const Resource* getResource(std::size_t rIndex) const;
		const std::pair<std::string, std::string>* getLanguage(std::size_t rIndex) const;
		const std::pair<std::string, std::string>* getString(std::size_t rIndex) const;
		const Resource* getResourceWithName(const std::string &rName) const;
		const Resource* getResourceWithName(std::size_t rId) const;
		const Resource* getResourceWithType(const std::string &rType) const;
		const Resource* getResourceWithType(std::size_t rId) const;
		const Resource* getResourceWithLanguage(const std::string &rLan) const;
		const Resource* getResourceWithLanguage(std::size_t rId) const;
		const std::string& getResourceIconhashCrc32() const;
		const std::string& getResourceIconhashMd5() const;
		const std::string& getResourceIconhashSha256() const;
		const std::string& getResourceIconPerceptualAvgHash() const;
		const ResourceIconGroup* getPriorResourceIconGroup() const;
		const ResourceIcon* getIconForIconHash() const;
		/// @}

		/// @name Iterators
		/// @{
		resourcesIterator begin() const;
		resourcesIterator end() const;
		/// @}

		/// @name Other methods
		/// @{
		void computeIconHashes();
		void parseVersionInfoResources();
		void clear();
		void addResource(std::unique_ptr<Resource>&& newResource);
		void addResourceVersion(Resource *ver);
		void addResourceIcon(ResourceIcon *icon);
		void addResourceIconGroup(ResourceIconGroup *iGroup);
		void linkResourceIconGroups();
		bool hasResources() const;
		bool hasResourceWithName(const std::string &rName) const;
		bool hasResourceWithName(std::size_t rId) const;
		bool hasResourceWithType(const std::string &rType) const;
		bool hasResourceWithType(std::size_t rId) const;
		bool hasResourceWithLanguage(const std::string &rLan) const;
		bool hasResourceWithLanguage(std::size_t rId) const;
		void dump(std::string &dumpTable) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
