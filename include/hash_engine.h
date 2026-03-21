#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace imon {

class Sha256 {
public:
    Sha256();
    void update(const uint8_t* data, std::size_t len);
    void update(const char* data, std::size_t len);
    std::string finalHex();
    static std::string hashFile(const std::string& path);

private:
    void transform(const uint8_t* chunk);
    void pad();
    void revert(uint8_t* hash) const;

    uint8_t data_[64];
    uint32_t datalen_;
    uint64_t bitlen_;
    uint32_t state_[8];
};

} // namespace imon
