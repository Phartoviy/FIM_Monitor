#pragma once

#include "models.h"
#include <string>
#include <vector>

namespace imon {

class ReportGenerator {
public:
    std::string writeCsv(const std::string& reportDir,
                         const std::vector<SecurityEvent>& events) const;
};

} // namespace imon
