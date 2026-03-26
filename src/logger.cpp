#include "logger.h"
#include "utils.h"

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <unistd.h>

namespace imon {
namespace {

constexpr const char* kReset = "\033[0m";
constexpr const char* kInfoColor = "\033[36m";
constexpr const char* kWarnColor = "\033[33m";
constexpr const char* kErrorColor = "\033[31m";

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

bool colorsEnabled(bool stderrStream) {
    if (std::getenv("NO_COLOR") != nullptr) {
        return false;
    }
    if (std::getenv("CLICOLOR_FORCE") != nullptr || std::getenv("FORCE_COLOR") != nullptr) {
        return true;
    }
    const int fd = stderrStream ? STDERR_FILENO : STDOUT_FILENO;
    return ::isatty(fd) == 1;
}

const char* levelColor(const char* level) {
    std::string_view value(level);
    if (value == "INFO") return kInfoColor;
    if (value == "WARN") return kWarnColor;
    if (value == "ERROR") return kErrorColor;
    return nullptr;
}

const char* threatColor(int threatLevel) {
    if (threatLevel >= 9) return "\033[1;35m"; // critical: magenta
    if (threatLevel >= 7) return "\033[1;31m"; // high: red
    if (threatLevel >= 5) return "\033[1;33m"; // elevated: yellow
    if (threatLevel >= 3) return "\033[32m";   // medium: green
    return "\033[2;37m";                        // low: dim gray
}

} // namespace

void Logger::write(const char* level, const std::string& message, bool stderrStream) {
    auto& stream = stderrStream ? std::cerr : std::cout;
    const std::string timestamp = formatTimestampHuman(nowUnix());

    if (const char* color = colorsEnabled(stderrStream) ? levelColor(level) : nullptr) {
        stream << '[' << timestamp << "] [" << color << level << kReset << "] " << message << '\n';
    } else {
        stream << '[' << timestamp << "] [" << level << "] " << message << '\n';
    }
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
    writeThreatEvent(event);
}

void Logger::writeThreatEvent(const SecurityEvent& event) {
    const bool stderrStream = event.threatLevel >= 7;
    auto& stream = stderrStream ? std::cerr : std::cout;
    const std::string timestamp = formatTimestampHuman(nowUnix());
    const std::string message = describeSecurityEvent(event);
    const char* level = event.threatLevel >= 7 ? "SECURITY" : "EVENT";

    if (colorsEnabled(stderrStream)) {
        stream << '[' << timestamp << "] ["
               << threatColor(event.threatLevel) << level
               << ":L" << event.threatLevel << kReset << "] "
               << threatColor(event.threatLevel) << message << kReset << '\n';
    } else {
        stream << '[' << timestamp << "] [" << level << ":L" << event.threatLevel << "] "
               << message << '\n';
    }
    stream.flush();
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
