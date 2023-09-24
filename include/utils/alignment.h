/**
 * @file include/utils/alignment.h
 * @brief Declaration of aligning operations.
 */

#ifndef UTILS_ALIGNMENT_H
#define UTILS_ALIGNMENT_H

#include <cstdint>


namespace utils {

bool isAligned(
		std::uint64_t value,
		std::uint64_t alignment,
		std::uint64_t& remainder);

std::uint64_t alignDown(std::uint64_t value, std::uint64_t alignment);
std::uint64_t alignUp(std::uint64_t value, std::uint64_t alignment);

} // namespace utils


#endif
