#pragma once

#include "models.h"
#include <cstdint>
#include <filesystem>
#include <string>

namespace imon {

std::string trim(const std::string& value);
std::string toLower(std::string value);
std::string eventTypeToString(EventType type);
std::string fileTypeToString(FileType type);
std::string formatTimestamp(int64_t unixTime);
int64_t nowUnix();
void ensureParentDirectory(const std::filesystem::path& path);
std::string csvEscape(const std::string& value);

} // namespace imon
