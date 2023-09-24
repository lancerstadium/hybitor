/**
 * @file include/utils/filesystem.h
 * @brief Wrapper for conditional include of C++17 filesystem feature.
 */

#ifndef UTILS_FILESYSTEM_H
#define UTILS_FILESYSTEM_H

#if __has_include(<filesystem>)
	#include <filesystem>
	namespace fs = std::filesystem;

#elif __has_include(<experimental/filesystem>)
	#include <experimental/filesystem>
	namespace fs = std::experimental::filesystem;

#else
	#error "Compiler does not have C++17 filesystem feature."

#endif

#endif
