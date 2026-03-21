#include "baseline_storage.h"
#include "config_manager.h"
#include "file_scanner.h"
#include "inotify_monitor.h"
#include "integrity_analyzer.h"
#include "logger.h"
#include "report_generator.h"
#include "utils.h"

#include <exception>
#include <iostream>
#include <string>

using namespace imon;

namespace {

void printUsage(const char* program) {
    std::cerr << "Использование:\n"
              << "  " << program << " --init <config.conf>\n"
              << "  " << program << " --scan <config.conf>\n"
              << "  " << program << " --monitor <config.conf>\n";
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
            Logger::info("Эталонная база создана: " + config.baselineFile);
            Logger::info("Количество записей: " + std::to_string(current.size()));
            return 0;
        }

        if (mode == "--scan") {
            const FileMap baseline = storage.load(config.baselineFile);
            const FileMap current = scanner.scan(config);

            IntegrityAnalyzer analyzer;
            const auto events = analyzer.analyze(baseline, current, config);

            ReportGenerator generator;
            const std::string reportPath = generator.writeCsv(config.reportDir, events);

            Logger::info("Проверка завершена. Событий: " + std::to_string(events.size()));
            Logger::info("Отчет: " + reportPath);

            for (const auto& event : events) {
                Logger::event(event);
            }
            return 0;
        }

        if (mode == "--monitor") {
            InotifyMonitor monitor;
            monitor.run(config);
            return 0;
        }

        printUsage(argv[0]);
        return 1;
    } catch (const std::exception& ex) {
        Logger::error(std::string("Ошибка: ") + ex.what());
        return 2;
    }
}
