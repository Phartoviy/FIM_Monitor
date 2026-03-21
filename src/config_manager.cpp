#include "config_manager.h"
#include "utils.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace imon {

Config ConfigManager::loadFromFile(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Не удалось открыть файл конфигурации: " + path);
    }

    Config config;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }

        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }

        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));

        if (key == "baseline_file") {
            config.baselineFile = value;
        } else if (key == "report_dir") {
            config.reportDir = value;
        } else if (key == "self_path") {
            config.selfPath = value;
        } else if (key == "watch") {
            config.watchDirs.push_back(value);
        } else if (key == "exclude") {
            config.excludePaths.push_back(value);
        }
    }

    if (config.baselineFile.empty()) {
        throw std::runtime_error("В конфигурации отсутствует baseline_file");
    }
    if (config.reportDir.empty()) {
        throw std::runtime_error("В конфигурации отсутствует report_dir");
    }
    if (config.watchDirs.empty()) {
        throw std::runtime_error("В конфигурации не задан ни один watch каталог");
    }

    return config;
}

} // namespace imon
