#include "report_generator.h"
#include "utils.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace imon {

std::string ReportGenerator::writeCsv(const std::string& reportDir,
                                      const std::vector<SecurityEvent>& events) const {
    fs::create_directories(reportDir);
    const std::string outputPath = (fs::path(reportDir) / ("integrity_report_" + formatTimestamp(nowUnix()) + ".csv")).string();

    std::ofstream out(outputPath);
    if (!out) {
        throw std::runtime_error("Не удалось создать CSV отчет: " + outputPath);
    }

    out << "timestamp,event_type,threat_level,path,description,old_hash,new_hash,old_mode,new_mode,old_uid,new_uid,old_gid,new_gid,old_symlink,new_symlink\n";
    for (const auto& event : events) {
        out << csvEscape(formatTimestamp(event.detectedAt)) << ','
            << csvEscape(eventTypeToString(event.eventType)) << ','
            << event.threatLevel << ','
            << csvEscape(event.path) << ','
            << csvEscape(event.description) << ','
            << csvEscape(event.oldRecord.sha256) << ','
            << csvEscape(event.newRecord.sha256) << ','
            << event.oldRecord.mode << ','
            << event.newRecord.mode << ','
            << event.oldRecord.uid << ','
            << event.newRecord.uid << ','
            << event.oldRecord.gid << ','
            << event.newRecord.gid << ','
            << csvEscape(event.oldRecord.symlinkTarget) << ','
            << csvEscape(event.newRecord.symlinkTarget) << '\n';
    }

    return outputPath;
}

} // namespace imon
