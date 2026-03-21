#pragma once

#include "config_manager.h"
#include "models.h"
#include "threat_classifier.h"
#include <vector>

namespace imon {

class IntegrityAnalyzer {
public:
    std::vector<SecurityEvent> analyze(const FileMap& baseline,
                                       const FileMap& current,
                                       const Config& config) const;

private:
    ThreatClassifier classifier_;
};

} // namespace imon
