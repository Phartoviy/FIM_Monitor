#pragma once

#include "models.h"

#include <string>

namespace imon {

class Logger {
public:
    static void info(const std::string& message);
    static void warning(const std::string& message);
    static void error(const std::string& message);
    static void event(const SecurityEvent& event);

private:
    static void write(const char* level, const std::string& message, bool stderrStream = false);
    static void writeThreatEvent(const SecurityEvent& event);
};

std::string describeSecurityEvent(const SecurityEvent& event);

} // namespace imon
