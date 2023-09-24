/**
* @file include/utils/array.h
* @brief Array utilities.
*/

#ifndef UTILS_ARRAY_H
#define UTILS_ARRAY_H

#include <cstddef>


namespace utils {

/**
* @brief Returns the number of elements of the given array as a compile-time
*        constant.
*
* Usage example:
* @code
* int array[10];
* int other_array[arraySize(array)]; // will have 10 elements
* @endcode
*/
// The array parameter has no name because we care only about the number of
// elements it contains.
template<typename T, std::size_t N>
constexpr std::size_t arraySize(T (&)[N]) noexcept {
	return N;
}

} // namespace utils

#endif
