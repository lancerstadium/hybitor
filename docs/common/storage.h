/**
 * @file include/common/storage.h
 * @brief Common object storage representation.
 */

#ifndef COMMON_STORAGE_H
#define COMMON_STORAGE_H

#include <string>
#include <optional>

#include "common/address.h"


namespace common {

/**
 * Represents possible storages of objects, function returns, etc.
 */
class Storage
{
	public:
		enum class eType
		{
			UNDEFINED = 0,
			GLOBAL,
			REGISTER,
			STACK
		};

	public:
		Storage();

		/// @name Storage named constructors.
		/// @{
		static Storage undefined();
		static Storage onStack(int offset);
		static Storage onStack(int offset, unsigned registerNumber);
		static Storage inMemory(const common::Address& address);
		static Storage inRegister(const std::string& registerName);
		static Storage inRegister(unsigned registerNumber);
		static Storage inRegister(
				const std::string& registerName,
				unsigned registerNumber);
		/// @}

		/// @name Storage query methods.
		/// @{
		bool isDefined() const;
		bool isUndefined() const;
		bool isMemory() const;
		bool isMemory(common::Address& globalAddress) const;
		bool isRegister() const;
		bool isRegister(std::string& registerName) const;
		bool isRegister(int& registerNumber) const;
		bool isStack() const;
		bool isStack(int& stackOffset) const;
		/// @}

		/// @name Storage get methods.
		/// @{
		common::Address getAddress() const;
		std::string getRegisterName() const;
		int getStackOffset() const;
		std::optional<unsigned> getRegisterNumber() const;
		/// @}

		/// @name Storage set methods.
		/// @{
		void setRegisterNumber(unsigned registerNumber);
		/// @}

	protected:
		const static int UNDEF_REG_NUM = -1;

	protected:
		eType type = eType::UNDEFINED;

		int _stackOffset = 0;
		std::string _registerName;
		common::Address _globalAddress;

		std::optional<unsigned> _registerNumber;
};

} // namespace common


#endif
