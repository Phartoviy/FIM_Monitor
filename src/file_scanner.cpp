#include "file_scanner.h"
#include "hash_engine.h"

#include <array>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace imon {

bool FileScanner::shouldExclude(const std::string& path, const Config& config) const {
    for (const auto& excluded : config.excludePaths) {
        if (path == excluded || (path.size() > excluded.size() && path.rfind(excluded + "/", 0) == 0)) {
            return true;
        }
    }
    return false;
}

FileRecord FileScanner::buildRecord(const std::string& path) const {
    struct stat st {};
    if (lstat(path.c_str(), &st) != 0) {
        throw std::runtime_error("Не удалось получить атрибуты файла: " + path);
    }

    FileRecord record;
    record.path = path;
    record.size = static_cast<uint64_t>(st.st_size);
    record.uid = static_cast<uint32_t>(st.st_uid);
    record.gid = static_cast<uint32_t>(st.st_gid);
    record.mode = static_cast<uint32_t>(st.st_mode & 07777);
    record.mtime = static_cast<int64_t>(st.st_mtime);
    record.ctime = static_cast<int64_t>(st.st_ctime);

    if (S_ISREG(st.st_mode)) {
        record.type = FileType::Regular;
        record.sha256 = Sha256::hashFile(path);
    } else if (S_ISDIR(st.st_mode)) {
        record.type = FileType::Directory;
    } else if (S_ISLNK(st.st_mode)) {
        record.type = FileType::Symlink;
        std::array<char, PATH_MAX> buffer{};
        const auto len = readlink(path.c_str(), buffer.data(), buffer.size() - 1);
        if (len >= 0) {
            buffer[static_cast<std::size_t>(len)] = '\0';
            record.symlinkTarget = buffer.data();
        }
    } else {
        record.type = FileType::Other;
    }

    return record;
}

FileMap FileScanner::scan(const Config& config) const {
    FileMap records;

    for (const auto& watchDir : config.watchDirs) {
        if (!fs::exists(watchDir)) {
            continue;
        }
        if (shouldExclude(watchDir, config)) {
            continue;
        }

        try {
            records.emplace(watchDir, buildRecord(watchDir));
        } catch (...) {
        }

        fs::recursive_directory_iterator it(
            watchDir,
            fs::directory_options::skip_permission_denied);
        fs::recursive_directory_iterator end;

        while (it != end) {
            std::error_code ec;
            const auto path = it->path().string();
            if (shouldExclude(path, config)) {
                it.disable_recursion_pending();
                ++it;
                continue;
            }

            try {
                records[path] = buildRecord(path);
            } catch (...) {
            }

            ++it;
        }
    }

    return records;
}

} // namespace imon
