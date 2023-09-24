/**
 * @file include/retdec/utils/binary_path.h
 * @brief Absolute path of currently running binary getters.
 */

#ifndef UTILS_BINARY_PATH_H
#define UTILS_BINARY_PATH_H

#include "utils/filesystem.h"


namespace utils {

fs::path getThisBinaryPath();
fs::path getThisBinaryDirectoryPath();

} // namespace utils


#endif
