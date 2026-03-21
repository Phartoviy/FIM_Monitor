#pragma once

#include "config_manager.h"
#include "models.h"

namespace imon {

class ThreatClassifier {
public:
    int classify(SecurityEvent& event, const Config& config) const;

private:
    int classifyBaseByPath(const std::string& path, const Config& config) const;
};

} // namespace imon
