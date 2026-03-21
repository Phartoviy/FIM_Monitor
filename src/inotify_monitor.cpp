#include "inotify_monitor.h"

#include "baseline_storage.h"
#include "file_scanner.h"
#include "integrity_analyzer.h"
#include "logger.h"
#include "report_generator.h"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <sys/inotify.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;

namespace imon {
namespace {

constexpr uint32_t kWatchMask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB |
                                IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF |
                                IN_MOVE_SELF | IN_CLOSE_WRITE | IN_ONLYDIR;

class InotifyFd {
public:
    explicit InotifyFd(int fd) : fd_(fd) {}
    ~InotifyFd() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    int get() const { return fd_; }
private:
    int fd_;
};

bool isPathUnder(const std::string& path, const std::string& base) {
    return path == base || (path.size() > base.size() && path.rfind(base + "/", 0) == 0);
}

bool shouldExclude(const std::string& path, const Config& config) {
    for (const auto& excluded : config.excludePaths) {
        if (isPathUnder(path, excluded)) {
            return true;
        }
    }
    return false;
}

void addWatchRecursive(int fd,
                       const std::string& root,
                       const Config& config,
                       std::unordered_map<int, std::string>& wdToPath) {
    auto addOne = [&](const std::string& dir) {
        if (shouldExclude(dir, config) || !fs::exists(dir) || !fs::is_directory(dir)) {
            return;
        }
        const int wd = inotify_add_watch(fd, dir.c_str(), kWatchMask);
        if (wd < 0) {
            std::ostringstream out;
            out << "Не удалось добавить inotify watch для каталога " << dir
                << ": " << std::strerror(errno);
            Logger::warning(out.str());
            return;
        }
        wdToPath[wd] = dir;
        Logger::info("Добавлен watch: " + dir);
    };

    addOne(root);
    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied), end;
         it != end; ++it) {
        std::error_code ec;
        const auto path = it->path().string();
        if (shouldExclude(path, config)) {
            it.disable_recursion_pending();
            continue;
        }
        if (it->is_directory(ec) && !ec) {
            addOne(path);
        }
    }
}

std::string maskToText(uint32_t mask) {
    std::vector<std::string> parts;
    if (mask & IN_CREATE) parts.emplace_back("CREATE");
    if (mask & IN_DELETE) parts.emplace_back("DELETE");
    if (mask & IN_MODIFY) parts.emplace_back("MODIFY");
    if (mask & IN_ATTRIB) parts.emplace_back("ATTRIB");
    if (mask & IN_MOVED_FROM) parts.emplace_back("MOVED_FROM");
    if (mask & IN_MOVED_TO) parts.emplace_back("MOVED_TO");
    if (mask & IN_CLOSE_WRITE) parts.emplace_back("CLOSE_WRITE");
    if (mask & IN_DELETE_SELF) parts.emplace_back("DELETE_SELF");
    if (mask & IN_MOVE_SELF) parts.emplace_back("MOVE_SELF");
    if (mask & IN_ISDIR) parts.emplace_back("ISDIR");
    if (mask & IN_IGNORED) parts.emplace_back("IGNORED");

    std::ostringstream out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out << '|';
        out << parts[i];
    }
    return out.str().empty() ? "UNKNOWN" : out.str();
}

} // namespace

void InotifyMonitor::run(const Config& config) const {
    BaselineStorage storage;
    FileScanner scanner;
    IntegrityAnalyzer analyzer;
    ReportGenerator reportGenerator;

    FileMap baseline = storage.load(config.baselineFile);

    const int fd = inotify_init1(0);
    if (fd < 0) {
        throw std::runtime_error(std::string("Не удалось инициализировать inotify: ") + std::strerror(errno));
    }
    InotifyFd fdHolder(fd);

    std::unordered_map<int, std::string> wdToPath;
    for (const auto& watchDir : config.watchDirs) {
        if (!fs::exists(watchDir)) {
            Logger::warning("Каталог наблюдения не существует, пропускаю: " + watchDir);
            continue;
        }
        addWatchRecursive(fd, watchDir, config, wdToPath);
    }

    if (wdToPath.empty()) {
        throw std::runtime_error("Не удалось добавить ни одного каталога в inotify watch list");
    }

    Logger::info("Мониторинг запущен в режиме inotify. Каталогов под наблюдением: " + std::to_string(wdToPath.size()));

    std::vector<char> buffer(64 * 1024);
    while (true) {
        const ssize_t length = read(fd, buffer.data(), buffer.size());
        if (length < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(std::string("Ошибка чтения событий inotify: ") + std::strerror(errno));
        }

        bool needRescan = false;
        for (char* ptr = buffer.data(); ptr < buffer.data() + length; ) {
            const auto* event = reinterpret_cast<const struct inotify_event*>(ptr);
            const std::string baseDir = wdToPath.count(event->wd) ? wdToPath[event->wd] : std::string("<unknown>");
            const std::string name = (event->len > 0 && event->name[0] != '\0') ? std::string(event->name) : std::string();
            const std::string fullPath = name.empty() ? baseDir : (fs::path(baseDir) / name).string();

            Logger::info("Получено событие inotify: mask=" + maskToText(event->mask) + ", path=" + fullPath);

            if ((event->mask & (IN_CREATE | IN_MOVED_TO)) && (event->mask & IN_ISDIR) && !shouldExclude(fullPath, config)) {
                addWatchRecursive(fd, fullPath, config, wdToPath);
            }
            if (event->mask & IN_IGNORED) {
                wdToPath.erase(event->wd);
            }
            if (event->mask & (IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF)) {
                needRescan = true;
            }

            ptr += sizeof(struct inotify_event) + event->len;
        }

        if (!needRescan) {
            continue;
        }

        const FileMap current = scanner.scan(config);
        const auto events = analyzer.analyze(baseline, current, config);

        if (events.empty()) {
            Logger::info("Изменения зафиксированы inotify, но отклонений от baseline не обнаружено");
            baseline = current;
            storage.save(config.baselineFile, baseline);
            continue;
        }

        const std::string reportPath = reportGenerator.writeCsv(config.reportDir, events);
        Logger::info("Сформирован CSV-отчет: " + reportPath + ", событий=" + std::to_string(events.size()));
        for (const auto& securityEvent : events) {
            Logger::event(securityEvent);
        }

        baseline = current;
        storage.save(config.baselineFile, baseline);
        Logger::info("Baseline обновлен после обработки событий");
    }
}

} // namespace imon
