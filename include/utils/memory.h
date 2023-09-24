/**
* @file include/utils/memory.h
* @brief Memory utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef UTILS_MEMORY_H
#define UTILS_MEMORY_H

#include <cstdlib>


namespace utils {

std::size_t getTotalSystemMemory();
bool limitSystemMemory(std::size_t limit);
bool limitSystemMemoryToHalfOfTotalSystemMemory();

} // namespace utils


#endif
