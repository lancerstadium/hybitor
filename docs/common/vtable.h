/**
 * @file include/common/vtable.h
 * @brief Common vtable representation.
 */

#ifndef COMMON_VTABLE_H
#define COMMON_VTABLE_H

#include <set>
#include <string>

#include <common/address.h>


namespace common {

/**
 * Represents C++ virtual table.
 * Table address is its unique ID.
 */
class VtableItem
{
	public:
		VtableItem(const common::Address& a
				= common::Address::Undefined,
				const common::Address& target
				= common::Address::Undefined,
				bool isThumb = false);

		/// @name VtableItem set methods.
		/// @{
		void setAddress(const common::Address& a);
		void setTargetFunctionAddress(const common::Address& a);
		void setTargetFunctionName(const std::string& n);
		void setIsThumb(bool isThumb);
		/// @}

		/// @name VtableItem get methods.
		/// @{
		common::Address getId() const;
		common::Address getAddress() const;
		common::Address getTargetFunctionAddress() const;
		std::string getTargetFunctionName() const;
		bool isThumb() const;
		/// @}

		bool operator<(const VtableItem& o) const;
		bool operator==(const VtableItem& o) const;

	private:
		/// Virtual table item's address in binary file.
		common::Address _address;
		/// Virtual function address for this item.
		common::Address _targetAddress;
		/// Name (unique ID) of function on target address.
		std::string _targetFunctionName;
		/// Is the target function a THUMB function?
		/// This typically means that its address in the table was odd.
		bool _isThumb = false;
};

/**
 * Represents virtual table.
 * Table's address in binary file is its unique ID.
 */
class Vtable
{
	public:
		Vtable(const common::Address& a
				= common::Address::Undefined);

		/// @name Vtable set methods.
		/// @{
		void setAddress(const common::Address& a);
		void setName(const std::string& n);
		/// @}

		/// @name Vtable get methods.
		/// @{
		common::Address getId() const;
		common::Address getAddress() const;
		std::string getName() const;
		/// @}

		bool operator<(const Vtable& o) const;
		bool operator==(const Vtable& o) const;

	public:
		std::set<VtableItem> items;

	private:
		std::string _name;
		/// Virtual table's address in binary file.
		common::Address _address;
};

/**
 * An associative container with virtual function tables' addresses as the key.
 * See Vtable class for details.
 */
using VtableContainer = std::set<Vtable>;

} // namespace common


#endif
