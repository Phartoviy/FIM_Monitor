#pragma once

#include <string>
#include <vector>

namespace imon {

struct Config {
    std::string baselineFile;
    std::string reportDir;
    std::string selfPath;
    std::vector<std::string> watchDirs;
    std::vector<std::string> excludePaths;
};

class ConfigManager {
public:
    static Config loadFromFile(const std::string& path);
};

} // namespace imon
