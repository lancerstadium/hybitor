/**
 * @file include/common/address.h
 * @brief 地址、地址对和其他派生类表示。
 */

#ifndef COMMON_ADDRESS_H
#define COMMON_ADDRESS_H

#include <cstddef>
#include <ostream>
#include <set>
#include <sstream>

#include "common/range.h"


namespace common {

class Address
{
	public:
		Address();
		Address(uint64_t a);
		explicit Address(const std::string &a);
		operator uint64_t() const;
		explicit operator bool() const;

		Address& operator++();
		Address operator++(int);
		Address& operator--();
		Address operator--(int);
		Address& operator+=(const Address& rhs);
		Address& operator-=(const Address& rhs);
		Address& operator|=(const Address& rhs);

		bool isUndefined() const;
		bool isDefined() const;

		uint64_t getValue() const;

		std::string toHexString() const;
		std::string toHexPrefixString() const;
		friend std::ostream& operator<< (std::ostream &out, const Address &a);

	public:
		static const uint64_t Undefined;

	private:
		uint64_t address;
};

using AddressRange = Range<Address>;
AddressRange stringToAddrRange(const std::string &r);

using AddressRangeContainer = RangeContainer<Address>;

} // namespace common


#endif
