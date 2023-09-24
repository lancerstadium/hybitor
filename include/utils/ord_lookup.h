/**
 * @file include/utils/ord_lookup.h
 * @brief Converts well-known ordinals to function names
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UTILS_ORD_LOOKUP_H
#define UTILS_ORD_LOOKUP_H


namespace utils {

std::string ordLookUp(const std::string& libName, const std::size_t& ordNum, bool forceNameFromOrdinal);

} // namespace utils


#endif
