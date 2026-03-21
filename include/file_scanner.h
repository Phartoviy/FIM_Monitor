#pragma once

#include "config_manager.h"
#include "models.h"

namespace imon {

class FileScanner {
public:
    FileMap scan(const Config& config) const;

private:
    bool shouldExclude(const std::string& path, const Config& config) const;
    FileRecord buildRecord(const std::string& path) const;
};

} // namespace imon
