/**
 * @file include/utils/debug.h
 * @brief Debug logging module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UTILS_DEBUG_H
#define UTILS_DEBUG_H

/// Loging msg print macro.
/// Define macro LOG_ENABLED to @c true before including this header to enable logging.
///
#define LOG \
	if (!LOG_ENABLED) {} \
	else std::cout

#endif
