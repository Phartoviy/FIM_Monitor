#include "logger.h"
#include "utils.h"

#include <iostream>
#include <sstream>

namespace imon {
namespace {

std::string fileRecordBrief(const FileRecord& record) {
    std::ostringstream out;
    out << "type=" << fileTypeToString(record.type)
        << ", mode=" << std::oct << record.mode << std::dec
        << ", uid=" << record.uid
        << ", gid=" << record.gid
        << ", size=" << record.size;

    if (!record.sha256.empty()) {
        out << ", sha256=" << record.sha256;
    }
    if (!record.symlinkTarget.empty()) {
        out << ", symlink_target=" << record.symlinkTarget;
    }
    return out.str();
}

} // namespace

void Logger::write(const char* level, const std::string& message, bool stderrStream) {
    auto& stream = stderrStream ? std::cerr : std::cout;
    stream << '[' << formatTimestampHuman(nowUnix()) << "] [" << level << "] " << message << '\n';
    stream.flush();
}

void Logger::info(const std::string& message) {
    write("INFO", message);
}

void Logger::warning(const std::string& message) {
    write("WARN", message);
}

void Logger::error(const std::string& message) {
    write("ERROR", message, true);
}

void Logger::event(const SecurityEvent& event) {
    const std::string prefix = event.threatLevel >= 7 ? "SECURITY" : "EVENT";
    write(prefix.c_str(), describeSecurityEvent(event), event.threatLevel >= 7);
}

std::string describeSecurityEvent(const SecurityEvent& event) {
    std::ostringstream out;
    out << "time=" << formatTimestampHuman(event.detectedAt)
        << ", level=" << event.threatLevel
        << ", event=" << eventTypeToString(event.eventType)
        << ", path=" << event.path
        << ", description=\"" << event.description << '"';

    switch (event.eventType) {
        case EventType::Created:
            out << ", new={" << fileRecordBrief(event.newRecord) << '}';
            break;
        case EventType::Deleted:
            out << ", old={" << fileRecordBrief(event.oldRecord) << '}';
            break;
        case EventType::ContentModified:
        case EventType::MetadataModified:
        case EventType::TypeChanged:
            out << ", old={" << fileRecordBrief(event.oldRecord) << '}'
                << ", new={" << fileRecordBrief(event.newRecord) << '}';
            break;
    }

    return out.str();
}

} // namespace imon
