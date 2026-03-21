#include "baseline_storage.h"
#include "utils.h"

#include <cstdint>
#include <fstream>
#include <stdexcept>

namespace imon {
namespace {

constexpr uint32_t kMagic = 0x494d4f4e;
constexpr uint32_t kVersion = 1;

void writeString(std::ofstream& out, const std::string& value) {
    const auto size = static_cast<uint32_t>(value.size());
    out.write(reinterpret_cast<const char*>(&size), sizeof(size));
    out.write(value.data(), static_cast<std::streamsize>(value.size()));
}

std::string readString(std::ifstream& in) {
    uint32_t size = 0;
    in.read(reinterpret_cast<char*>(&size), sizeof(size));
    std::string value(size, '\0');
    if (size > 0) {
        in.read(value.data(), static_cast<std::streamsize>(size));
    }
    return value;
}

} // namespace

void BaselineStorage::save(const std::string& path, const FileMap& records) const {
    ensureParentDirectory(path);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Не удалось открыть baseline для записи: " + path);
    }

    out.write(reinterpret_cast<const char*>(&kMagic), sizeof(kMagic));
    out.write(reinterpret_cast<const char*>(&kVersion), sizeof(kVersion));
    const auto count = static_cast<uint64_t>(records.size());
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& [_, record] : records) {
        writeString(out, record.path);
        const auto type = static_cast<uint8_t>(record.type);
        out.write(reinterpret_cast<const char*>(&type), sizeof(type));
        out.write(reinterpret_cast<const char*>(&record.size), sizeof(record.size));
        out.write(reinterpret_cast<const char*>(&record.uid), sizeof(record.uid));
        out.write(reinterpret_cast<const char*>(&record.gid), sizeof(record.gid));
        out.write(reinterpret_cast<const char*>(&record.mode), sizeof(record.mode));
        out.write(reinterpret_cast<const char*>(&record.mtime), sizeof(record.mtime));
        out.write(reinterpret_cast<const char*>(&record.ctime), sizeof(record.ctime));
        writeString(out, record.symlinkTarget);
        writeString(out, record.sha256);
    }
}

FileMap BaselineStorage::load(const std::string& path) const {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Не удалось открыть baseline для чтения: " + path);
    }

    uint32_t magic = 0;
    uint32_t version = 0;
    uint64_t count = 0;
    in.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    in.read(reinterpret_cast<char*>(&version), sizeof(version));
    in.read(reinterpret_cast<char*>(&count), sizeof(count));

    if (magic != kMagic) {
        throw std::runtime_error("Некорректный magic baseline файла");
    }
    if (version != kVersion) {
        throw std::runtime_error("Неподдерживаемая версия baseline файла");
    }

    FileMap result;
    for (uint64_t i = 0; i < count; ++i) {
        FileRecord record;
        record.path = readString(in);
        uint8_t type = 0;
        in.read(reinterpret_cast<char*>(&type), sizeof(type));
        record.type = static_cast<FileType>(type);
        in.read(reinterpret_cast<char*>(&record.size), sizeof(record.size));
        in.read(reinterpret_cast<char*>(&record.uid), sizeof(record.uid));
        in.read(reinterpret_cast<char*>(&record.gid), sizeof(record.gid));
        in.read(reinterpret_cast<char*>(&record.mode), sizeof(record.mode));
        in.read(reinterpret_cast<char*>(&record.mtime), sizeof(record.mtime));
        in.read(reinterpret_cast<char*>(&record.ctime), sizeof(record.ctime));
        record.symlinkTarget = readString(in);
        record.sha256 = readString(in);
        result[record.path] = record;
    }

    return result;
}

} // namespace imon
