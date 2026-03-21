#pragma once

#include "config_manager.h"

namespace imon {

class InotifyMonitor {
public:
    void run(const Config& config) const;
};

} // namespace imon
