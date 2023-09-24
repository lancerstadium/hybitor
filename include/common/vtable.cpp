/**
 * @file include/common/vtable.cpp
 * @brief Common vtable representation.
 */

#include "common/vtable.h"
#include "common/address.h"


namespace common {

//
//=============================================================================
// VtableItem
//=============================================================================
//

VtableItem::VtableItem(
		const common::Address& a,
		const common::Address& target,
		bool isThumb)
		: _address(a)
		, _targetAddress(target)
		, _isThumb(isThumb)
{

}

void VtableItem::setAddress(const common::Address& a)
{
	_address = a;
}

void VtableItem::setTargetFunctionAddress(const common::Address& a)
{
	_targetAddress = a;
}

void VtableItem::setTargetFunctionName(const std::string& n)
{
	_targetFunctionName = n;
}

void VtableItem::setIsThumb(bool isThumb)
{
	_isThumb = isThumb;
}

common::Address VtableItem::getId() const
{
	return getAddress();
}

/**
 * @return Virtual table item's address in binary file.
 */
common::Address VtableItem::getAddress() const
{
	return _address;
}

/**
 * @return Virtual function address for this item.
 */
common::Address VtableItem::getTargetFunctionAddress() const
{
	return _targetAddress;
}

/**
 * @return Name (unique ID) of function on target address.
 */
std::string VtableItem::getTargetFunctionName() const
{
	return _targetFunctionName;
}

bool VtableItem::isThumb() const
{
	return _isThumb;
}

/**
 * Virtual table items are ordered by their addresses in binary file.
 */
bool VtableItem::operator<(const VtableItem& o) const
{
	return getAddress() < o.getAddress();
}

/**
 * Two virtual table items are equal if their addresses in binary file
 * are equal.
 */
bool VtableItem::operator==(const VtableItem& o) const
{
	return getAddress() == o.getAddress();
}

//
//=============================================================================
// Vtable
//=============================================================================
//

Vtable::Vtable(const common::Address& a) :
		_address(a)
{

}

void Vtable::setAddress(const common::Address& a)
{
	_address = a;
}

void Vtable::setName(const std::string& n)
{
	_name = n;
}

common::Address Vtable::getId() const
{
	return getAddress();
}

/**
 * @return Virtual table's address in binary file.
 */
common::Address Vtable::getAddress() const
{
	return _address;
}

std::string Vtable::getName() const
{
	return _name;
}

/**
 * Virtual tables are ordered by their addresses in binary file.
 */
bool Vtable::operator<(const Vtable& o) const
{
	return getAddress() < o.getAddress();
}

/**
 * Two virtual tables are equal if their addresses in binary file
 * are equal.
 */
bool Vtable::operator==(const Vtable& o) const
{
	return getAddress() == o.getAddress();
}

} // namespace common

