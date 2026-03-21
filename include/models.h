#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace imon {

enum class FileType : uint8_t {
    Regular = 0,
    Directory = 1,
    Symlink = 2,
    Other = 3
};

enum class EventType : uint8_t {
    Created = 0,
    Deleted = 1,
    ContentModified = 2,
    MetadataModified = 3,
    TypeChanged = 4
};

struct FileRecord {
    std::string path;
    FileType type = FileType::Other;
    uint64_t size = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint32_t mode = 0;
    int64_t mtime = 0;
    int64_t ctime = 0;
    std::string symlinkTarget;
    std::string sha256;
};

struct SecurityEvent {
    EventType eventType = EventType::Created;
    std::string path;
    int threatLevel = 0;
    std::string description;
    FileRecord oldRecord;
    FileRecord newRecord;
    int64_t detectedAt = 0;
};

using FileMap = std::unordered_map<std::string, FileRecord>;

} // namespace imon
