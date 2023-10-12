/**
 * @file include/common/language.h
 * @brief Common programming language representation.
 */

#ifndef COMMON_LANGUAGE_H
#define COMMON_LANGUAGE_H

#include <set>
#include <string>


namespace common {

/**
 * Represents input binary's language.
 * Language's name is its unique ID.
 */
class Language
{
	public:
		Language();
		Language(const std::string& langName);

		/// @name Language query methods.
		/// @{
		bool isUnknown() const;
		bool isKnown() const;
		bool isModuleCountSet() const;
		bool isBytecode() const;
		/// @}

		/// @name Language set methods.
		/// @{
		void setName(const std::string& n);
		void setIsUnknown();
		void setModuleCount(unsigned c);
		void setIsBytecode(bool b);
		/// @}

		/// @name Language get methods.
		/// @{
		std::string getName() const;
		unsigned getModuleCount() const;
		/// @}

		bool operator<(const Language& val) const;
		bool operator==(const Language& val) const;

	private:
		/// Unique ID.
		std::string _name;
		int _moduleCount = -1;
		bool _bytecode = false;
};

/**
 * Set container with languages' names as unique ID (set key).
 * See Language class for details.
 */
class LanguageContainer : public std::set<Language>
{
	public:
		const Language* getFirstBytecode() const;
		bool hasLanguage(const std::string& sub) const;
};

} // namespace common


#endif
