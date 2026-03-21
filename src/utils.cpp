#include "utils.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <sstream>

namespace imon {

std::string trim(const std::string& value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string eventTypeToString(EventType type) {
    switch (type) {
        case EventType::Created: return "Created";
        case EventType::Deleted: return "Deleted";
        case EventType::ContentModified: return "ContentModified";
        case EventType::MetadataModified: return "MetadataModified";
        case EventType::TypeChanged: return "TypeChanged";
    }
    return "Unknown";
}

std::string fileTypeToString(FileType type) {
    switch (type) {
        case FileType::Regular: return "Regular";
        case FileType::Directory: return "Directory";
        case FileType::Symlink: return "Symlink";
        case FileType::Other: return "Other";
    }
    return "Other";
}

std::string formatTimestamp(int64_t unixTime) {
    std::time_t tt = static_cast<std::time_t>(unixTime);
    std::tm tm = *std::localtime(&tt);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S");
    return out.str();
}

std::string formatTimestampHuman(int64_t unixTime) {
    std::time_t tt = static_cast<std::time_t>(unixTime);
    std::tm tm = *std::localtime(&tt);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

int64_t nowUnix() {
    return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
}

void ensureParentDirectory(const std::filesystem::path& path) {
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
}

std::string csvEscape(const std::string& value) {
    std::string escaped = value;
    std::string::size_type pos = 0;
    while ((pos = escaped.find('"', pos)) != std::string::npos) {
        escaped.insert(pos, 1, '"');
        pos += 2;
    }
    return '"' + escaped + '"';
}

} // namespace imon
