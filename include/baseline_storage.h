#pragma once

#include "models.h"
#include <string>

namespace imon {

class BaselineStorage {
public:
    void save(const std::string& path, const FileMap& records) const;
    FileMap load(const std::string& path) const;
};

} // namespace imon
