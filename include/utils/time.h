/**
* @file include/retdec/utils/time.h
* @brief Time-related functions.
*/

#ifndef UTILS_TIME_H
#define UTILS_TIME_H

#include <ctime>
#include <string>

namespace utils {

std::tm *getCurrentTimestamp();
std::string getCurrentDate();
std::string getCurrentTime();
std::string getCurrentYear();
std::string timestampToDate(std::tm *tm);
std::string timestampToDate(std::time_t timestamp);
std::string timestampToGmtDatetime(std::time_t timestamp);

double getElapsedTime();

} // namespace utils

#endif
