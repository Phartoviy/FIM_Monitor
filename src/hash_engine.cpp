#include "hash_engine.h"

#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace imon {
namespace {

constexpr std::array<uint32_t, 64> kTable = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
inline uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
inline uint32_t ep0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t ep1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

} // namespace

Sha256::Sha256() : data_{0}, datalen_(0), bitlen_(0), state_{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
} {}

void Sha256::update(const char* data, std::size_t len) {
    update(reinterpret_cast<const uint8_t*>(data), len);
}

void Sha256::update(const uint8_t* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        data_[datalen_++] = data[i];
        if (datalen_ == 64) {
            transform(data_);
            bitlen_ += 512;
            datalen_ = 0;
        }
    }
}

void Sha256::transform(const uint8_t* chunk) {
    uint32_t m[64];
    for (uint32_t i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (static_cast<uint32_t>(chunk[j]) << 24) |
               (static_cast<uint32_t>(chunk[j + 1]) << 16) |
               (static_cast<uint32_t>(chunk[j + 2]) << 8) |
               (static_cast<uint32_t>(chunk[j + 3]));
    }
    for (uint32_t i = 16; i < 64; ++i) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    uint32_t a = state_[0];
    uint32_t b = state_[1];
    uint32_t c = state_[2];
    uint32_t d = state_[3];
    uint32_t e = state_[4];
    uint32_t f = state_[5];
    uint32_t g = state_[6];
    uint32_t h = state_[7];

    for (uint32_t i = 0; i < 64; ++i) {
        const uint32_t t1 = h + ep1(e) + choose(e, f, g) + kTable[i] + m[i];
        const uint32_t t2 = ep0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::pad() {
    uint32_t i = datalen_;

    if (datalen_ < 56) {
        data_[i++] = 0x80;
        while (i < 56) {
            data_[i++] = 0x00;
        }
    } else {
        data_[i++] = 0x80;
        while (i < 64) {
            data_[i++] = 0x00;
        }
        transform(data_);
        std::memset(data_, 0, 56);
    }

    bitlen_ += static_cast<uint64_t>(datalen_) * 8;
    data_[63] = static_cast<uint8_t>(bitlen_);
    data_[62] = static_cast<uint8_t>(bitlen_ >> 8);
    data_[61] = static_cast<uint8_t>(bitlen_ >> 16);
    data_[60] = static_cast<uint8_t>(bitlen_ >> 24);
    data_[59] = static_cast<uint8_t>(bitlen_ >> 32);
    data_[58] = static_cast<uint8_t>(bitlen_ >> 40);
    data_[57] = static_cast<uint8_t>(bitlen_ >> 48);
    data_[56] = static_cast<uint8_t>(bitlen_ >> 56);
    transform(data_);
}

void Sha256::revert(uint8_t* hash) const {
    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t j = 0; j < 8; ++j) {
            hash[i + (j * 4)] = static_cast<uint8_t>((state_[j] >> (24 - i * 8)) & 0x000000ff);
        }
    }
}

std::string Sha256::finalHex() {
    pad();
    uint8_t hash[32];
    revert(hash);

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }
    return out.str();
}

std::string Sha256::hashFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Не удалось открыть файл для хеширования: " + path);
    }

    Sha256 sha;
    std::array<char, 8192> buffer{};
    while (in.good()) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = static_cast<std::size_t>(in.gcount());
        if (count > 0) {
            sha.update(buffer.data(), count);
        }
    }
    return sha.finalHex();
}

} // namespace imon
