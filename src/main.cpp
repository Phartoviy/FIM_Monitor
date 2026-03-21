#include "baseline_storage.h"
#include "config_manager.h"
#include "file_scanner.h"
#include "integrity_analyzer.h"
#include "report_generator.h"
#include "utils.h"

#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

using namespace imon;

namespace {

void printUsage(const char* program) {
    std::cerr << "Использование:\n"
              << "  " << program << " --init <config.conf>\n"
              << "  " << program << " --scan <config.conf>\n";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printUsage(argv[0]);
        return 1;
    }

    try {
        const std::string mode = argv[1];
        const std::string configPath = argv[2];

        const Config config = ConfigManager::loadFromFile(configPath);
        FileScanner scanner;
        BaselineStorage storage;

        if (mode == "--init") {
            const FileMap current = scanner.scan(config);
            storage.save(config.baselineFile, current);
            std::cout << "Эталонная база создана: " << config.baselineFile << "\n";
            std::cout << "Количество записей: " << current.size() << "\n";
            return 0;
        }

        if (mode == "--scan") {
            const FileMap baseline = storage.load(config.baselineFile);
            const FileMap current = scanner.scan(config);

            IntegrityAnalyzer analyzer;
            const auto events = analyzer.analyze(baseline, current, config);

            ReportGenerator generator;
            const std::string reportPath = generator.writeCsv(config.reportDir, events);

            std::cout << "Проверка завершена. Событий: " << events.size() << "\n";
            std::cout << "Отчет: " << reportPath << "\n";

            for (const auto& event : events) {
                if (event.threatLevel >= 7) {
                    std::cout << "[CRITICAL] level=" << event.threatLevel
                              << " type=" << eventTypeToString(event.eventType)
                              << " path=" << event.path << "\n";
                }
            }
            return 0;
        }

        printUsage(argv[0]);
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Ошибка: " << ex.what() << "\n";
        return 2;
    }
}
