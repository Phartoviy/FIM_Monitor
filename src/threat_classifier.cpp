#include "threat_classifier.h"

#include <algorithm>

namespace imon {

int ThreatClassifier::classifyBaseByPath(const std::string& path, const Config& config) const {
    auto startsWith = [&](const std::string& prefix) {
        return path == prefix || (path.size() > prefix.size() && path.rfind(prefix + "/", 0) == 0);
    };
    auto containsSegment = [&](const std::string& segment) {
        return path == segment ||
               (path.size() > segment.size() && path.rfind(segment + "/", 0) == 0) ||
               path.find(segment + "/") != std::string::npos;
    };

    if (!config.selfPath.empty() && (path == config.selfPath || startsWith(config.baselineFile) || startsWith(config.reportDir))) {
        return 6;
    }
    if (containsSegment("/boot") || containsSegment("/lib/modules") || path.find("initramfs") != std::string::npos) {
        return 9;
    }
    if (containsSegment("/sbin") || containsSegment("/usr/sbin")) {
        return 8;
    }
    if (containsSegment("/bin") || containsSegment("/usr/bin")) {
        return 7;
    }
    if (containsSegment("/etc/pam.d") || path == "/etc/ssh/sshd_config" || path.find("/etc/ssh/sshd_config") != std::string::npos || path == "/etc/shadow" || path.find("/etc/shadow") != std::string::npos || path == "/etc/sudoers" || path.find("/etc/sudoers") != std::string::npos) {
        return 5;
    }
    if (containsSegment("/etc")) {
        return 4;
    }
    if (containsSegment("/lib") || containsSegment("/usr/lib") || containsSegment("/usr/lib64")) {
        return 3;
    }
    if (containsSegment("/root") || path.find("/home/admin") == 0) {
        return 2;
    }
    if (containsSegment("/tmp") || containsSegment("/var/tmp") || containsSegment("/dev/shm")) {
        return 1;
    }
    return 0;
}

int ThreatClassifier::classify(SecurityEvent& event, const Config& config) const {
    int level = classifyBaseByPath(event.path, config);

    switch (event.eventType) {
        case EventType::Deleted:
            level = std::min(9, level + 1);
            event.description = "Файл удален";
            break;
        case EventType::Created:
            if (level >= 7) {
                level = std::max(level, 7);
            }
            event.description = "Обнаружен новый файл";
            break;
        case EventType::ContentModified:
            if (level >= 5) {
                level = std::min(9, level + 1);
            }
            event.description = "Изменено содержимое файла";
            break;
        case EventType::MetadataModified:
            event.description = "Изменены метаданные файла";
            break;
        case EventType::TypeChanged:
            level = std::min(9, level + 1);
            event.description = "Изменен тип файлового объекта";
            break;
    }

    event.threatLevel = level;
    return level;
}

} // namespace imon
