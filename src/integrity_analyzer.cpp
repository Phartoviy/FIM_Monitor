#include "integrity_analyzer.h"
#include "utils.h"

namespace imon {

std::vector<SecurityEvent> IntegrityAnalyzer::analyze(const FileMap& baseline,
                                                      const FileMap& current,
                                                      const Config& config) const {
    std::vector<SecurityEvent> events;
    const int64_t detectedAt = nowUnix();

    for (const auto& [path, oldRecord] : baseline) {
        const auto currentIt = current.find(path);
        if (currentIt == current.end()) {
            SecurityEvent event;
            event.eventType = EventType::Deleted;
            event.path = path;
            event.oldRecord = oldRecord;
            event.detectedAt = detectedAt;
            classifier_.classify(event, config);
            events.push_back(event);
            continue;
        }

        const auto& newRecord = currentIt->second;
        if (oldRecord.type != newRecord.type) {
            SecurityEvent event;
            event.eventType = EventType::TypeChanged;
            event.path = path;
            event.oldRecord = oldRecord;
            event.newRecord = newRecord;
            event.detectedAt = detectedAt;
            classifier_.classify(event, config);
            events.push_back(event);
            continue;
        }

        const bool contentChanged = (oldRecord.sha256 != newRecord.sha256) ||
                                    (oldRecord.symlinkTarget != newRecord.symlinkTarget);
        const bool metadataChanged = oldRecord.mode != newRecord.mode ||
                                     oldRecord.uid != newRecord.uid ||
                                     oldRecord.gid != newRecord.gid ||
                                     oldRecord.mtime != newRecord.mtime ||
                                     oldRecord.ctime != newRecord.ctime ||
                                     oldRecord.size != newRecord.size;

        if (contentChanged) {
            SecurityEvent event;
            event.eventType = EventType::ContentModified;
            event.path = path;
            event.oldRecord = oldRecord;
            event.newRecord = newRecord;
            event.detectedAt = detectedAt;
            classifier_.classify(event, config);
            events.push_back(event);
        } else if (metadataChanged) {
            SecurityEvent event;
            event.eventType = EventType::MetadataModified;
            event.path = path;
            event.oldRecord = oldRecord;
            event.newRecord = newRecord;
            event.detectedAt = detectedAt;
            classifier_.classify(event, config);
            events.push_back(event);
        }
    }

    for (const auto& [path, newRecord] : current) {
        if (baseline.find(path) == baseline.end()) {
            SecurityEvent event;
            event.eventType = EventType::Created;
            event.path = path;
            event.newRecord = newRecord;
            event.detectedAt = detectedAt;
            classifier_.classify(event, config);
            events.push_back(event);
        }
    }

    return events;
}

} // namespace imon
