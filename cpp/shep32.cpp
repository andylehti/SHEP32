// g++ -std=c++17 -O2 shep_cli_polished.cpp audit.cpp -o shep -lcrypto -lz

#include <boost/multiprecision/cpp_int.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <limits>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <map>
#include <set>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <zlib.h>
#include "audit.h"

using namespace std;
using boost::multiprecision::cpp_int;

cpp_int parseDec(const string& s);
string trimStr(const string& s);

const string gCharBase = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`\"',_!#";
const string gAuxBase = "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const string KEY_HEADER = "-----BEGIN SHEP KEY-----\n";
const string KEY_FOOTER = "\n-----END SHEP KEY-----";
const string FILE_MARKER = "__shep_file__";
const uint64_t DEFAULT_MAX_BYTES = 1000ULL * 1024ULL;
const int CHUNK_UNIT = 2048;
const int FIXED_COUNT = 8;
namespace fs = std::filesystem;

string deriveCharset(size_t c) { return gCharBase.substr(0, c); }
string deriveAuxCharset() { return gAuxBase; }

string lowerStr(string s) {
    transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return char(tolower(c)); });
    return s;
}

vector<uint8_t> secureRandomBytes(size_t n) {
    vector<uint8_t> out(n);
    if (n && RAND_bytes(out.data(), static_cast<int>(n)) != 1) throw runtime_error("CSPRNG failed");
    return out;
}

cpp_int bytesToInt(const vector<uint8_t>& raw) {
    cpp_int out = 0;
    for (uint8_t b : raw) {
        out <<= 8;
        out += b;
    }
    return out;
}

static void appendUtf8(string& out, uint32_t cp) {
    if (cp <= 0x7F) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

vector<char16_t> decodeUtf8ToUtf16Units(const string& s) {
    vector<char16_t> out;
    size_t i = 0;
    while (i < s.size()) {
        uint8_t b0 = static_cast<uint8_t>(s[i]);
        uint32_t cp = 0;
        size_t need = 0;
        if (b0 < 0x80) {
            cp = b0;
            need = 1;
        } else if ((b0 & 0xE0) == 0xC0) {
            cp = b0 & 0x1F;
            need = 2;
        } else if ((b0 & 0xF0) == 0xE0) {
            cp = b0 & 0x0F;
            need = 3;
        } else if ((b0 & 0xF8) == 0xF0) {
            cp = b0 & 0x07;
            need = 4;
        } else {
            throw runtime_error("bad utf-8 input");
        }
        if (i + need > s.size()) throw runtime_error("truncated utf-8 input");
        for (size_t j = 1; j < need; ++j) {
            uint8_t bx = static_cast<uint8_t>(s[i + j]);
            if ((bx & 0xC0) != 0x80) throw runtime_error("bad utf-8 continuation");
            cp = (cp << 6) | (bx & 0x3F);
        }
        if ((need == 2 && cp < 0x80) || (need == 3 && cp < 0x800) || (need == 4 && cp < 0x10000) || cp > 0x10FFFF) {
            throw runtime_error("overlong or invalid utf-8 codepoint");
        }
        if (cp <= 0xFFFF) out.push_back(static_cast<char16_t>(cp));
        else {
            cp -= 0x10000;
            out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
            out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
        }
        i += need;
    }
    return out;
}

vector<uint8_t> encodeUtf16Le(const string& s) {
    vector<char16_t> units = decodeUtf8ToUtf16Units(s);
    vector<uint8_t> out;
    out.reserve(units.size() * 2);
    for (char16_t ch : units) {
        out.push_back(static_cast<uint8_t>(ch & 0xFF));
        out.push_back(static_cast<uint8_t>((ch >> 8) & 0xFF));
    }
    return out;
}

string bytesToHex(const vector<uint8_t>& data) {
    static const char lut[] = "0123456789abcdef";
    string out;
    out.resize(data.size() * 2);
    for (size_t i = 0; i < data.size(); ++i) {
        out[i * 2] = lut[data[i] >> 4];
        out[i * 2 + 1] = lut[data[i] & 0x0F];
    }
    return out;
}

vector<uint8_t> readFileBytes(const string& path) {
    ifstream fp(path, ios::binary);
    if (!fp) throw runtime_error("failed to open file: " + path);
    fp.seekg(0, ios::end);
    streamoff sz = fp.tellg();
    if (sz < 0) throw runtime_error("failed to read file size: " + path);
    fp.seekg(0, ios::beg);
    vector<uint8_t> raw(static_cast<size_t>(sz));
    if (sz > 0) fp.read(reinterpret_cast<char*>(raw.data()), sz);
    if (!fp && sz > 0) throw runtime_error("failed to read file: " + path);
    return raw;
}

uint64_t parseU64(const string& s, const string& label) {
    cpp_int v = parseDec(s);
    if (v < 0) throw runtime_error(label + " must be >= 0");
    if (v > numeric_limits<uint64_t>::max()) throw runtime_error(label + " exceeds uint64 range");
    return v.convert_to<uint64_t>();
}

inline uint8_t hexNibble(char ch) {
    if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
    if (ch >= 'a' && ch <= 'f') return static_cast<uint8_t>(ch - 'a' + 10);
    if (ch >= 'A' && ch <= 'F') return static_cast<uint8_t>(ch - 'A' + 10);
    throw runtime_error("bad hex digit");
}

inline int hexPairValue(const string& s, size_t i) {
    return (hexNibble(s[i]) << 4) | hexNibble(s[i + 1]);
}

inline void appendHexByte(string& out, uint8_t v) {
    static const char lut[] = "0123456789abcdef";
    out.push_back(lut[v >> 4]);
    out.push_back(lut[v & 0x0F]);
}

cpp_int parseBits(const string& s) {
    cpp_int out = 0;
    for (char ch : s) {
        out <<= 1;
        if (ch == '1') out += 1;
        else if (ch != '0') throw runtime_error("bad binary digit");
    }
    return out;
}

void incDecString(string& s) {
    if (s.empty()) { s = "1"; return; }
    if (s[0] == '-') {
        if (s == "-1") { s = "0"; return; }
        size_t i = s.size();
        while (i > 1 && s[i - 1] == '0') { s[i - 1] = '9'; --i; }
        if (i <= 1) throw runtime_error("bad negative decimal string");
        s[i - 1] = char(s[i - 1] - 1);
        size_t p = 1;
        while (p + 1 < s.size() && s[p] == '0') ++p;
        if (p > 1) s.erase(1, p - 1);
        if (s == "-0") s = "0";
        return;
    }
    size_t i = s.size();
    while (i > 0 && s[i - 1] == '9') { s[i - 1] = '0'; --i; }
    if (i == 0) s.insert(s.begin(), '1');
    else s[i - 1] = char(s[i - 1] + 1);
}

void printProgBar(const string& label, uint64_t done, uint64_t total, chrono::steady_clock::time_point started) {
    if (total == 0) return;
    const int barW = 30;
    long double frac = static_cast<long double>(done) / static_cast<long double>(total);
    if (frac < 0) frac = 0;
    if (frac > 1) frac = 1;
    int fill = static_cast<int>(frac * barW);
    auto elapsed = chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - started).count();
    ostringstream ss;
    ss << '\r' << label << " [";
    for (int i = 0; i < barW; ++i) ss << (i < fill ? '#' : '.');
    ss << "] " << setw(3) << static_cast<int>(frac * 100.0L) << "% " << done << '/' << total << " elapsed " << elapsed << 's';
    cerr << ss.str() << flush;
    if (done >= total) cerr << '\n';
}

void validateFileCap(const string& path, bool noLimit) {
    uint64_t size = fs::file_size(path);
    if (!noLimit && size > DEFAULT_MAX_BYTES) throw runtime_error("file exceeds default limit; use --no-limit to override");
}

int resolveChunkBytes(int chunkSizeUnits = 1, int chunkBytes = -1) {
    int out = chunkBytes > 0 ? chunkBytes : chunkSizeUnits * CHUNK_UNIT;
    if (out < 1) throw runtime_error("chunk size must be >= 1 byte");
    return out;
}

string readStdinPayload(const string& delim = "") {
    stringstream ss; ss << cin.rdbuf();
    string data = ss.str();
    if (delim.empty()) return trimStr(data);
    string start = delim + ":BEGIN", end = delim + ":END";
    size_t a = data.find(start), b = a == string::npos ? string::npos : data.find(end, a + start.size());
    if (a == string::npos || b == string::npos) throw runtime_error("delimiter block not found in stdin");
    return trimStr(data.substr(a + start.size(), b - (a + start.size())));
}

cpp_int parseDec(const string& s) {
    if (s.empty()) throw runtime_error("empty decimal string");
    cpp_int out = 0;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-') { neg = true; i = 1; }
    if (i >= s.size()) throw runtime_error("bad decimal string");
    for (; i < s.size(); ++i) {
        char ch = s[i];
        if (ch < '0' || ch > '9') throw runtime_error("bad decimal digit");
        out = out * 10 + (ch - '0');
    }
    return neg ? -out : out;
}

cpp_int parseStdBase(const string& s, int base) {
    if (s.empty()) throw runtime_error("empty parse string");
    cpp_int out = 0;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-') { neg = true; i = 1; }
    if (i >= s.size()) throw runtime_error("bad parse string");
    for (; i < s.size(); ++i) {
        char ch = s[i];
        int v;
        if (ch >= '0' && ch <= '9') v = ch - '0';
        else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
        else throw runtime_error("bad digit");
        if (v >= base) throw runtime_error("digit out of range");
        out = out * base + v;
    }
    return neg ? -out : out;
}

cpp_int powInt(cpp_int base, size_t exp) {
    cpp_int out = 1;
    while (exp > 0) {
        if (exp & 1) out *= base;
        exp >>= 1;
        if (exp) base *= base;
    }
    return out;
}

string decStr(const cpp_int& n) { return n.convert_to<string>(); }

string encodeHex(const cpp_int& n) {
    if (n == 0) return "0";
    bool neg = n < 0;
    cpp_int x = neg ? -n : n;
    stringstream ss;
    ss << hex << x;
    string s = ss.str();
    transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return char(tolower(c)); });
    return neg ? ("-" + s) : s;
}

string dropPrefixBit(const cpp_int& n) {
    cpp_int x = n;
    if (x < 0) x = -x;
    if (x == 0) return "";
    string out;
    while (x > 0) {
        out.push_back((x & 1) ? '1' : '0');
        x >>= 1;
    }
    reverse(out.begin(), out.end());
    return out.size() <= 1 ? "" : out.substr(1);
}

string leftPad(const cpp_int& v, int w) {
    string s = decStr(v);
    if ((int)s.size() >= w) return s;
    return string(w - (int)s.size(), '0') + s;
}

string truncatePrefix(const cpp_int& v, int n) {
    string s = decStr(v);
    if (n <= 0) return "";
    if ((int)s.size() >= n) return s.substr(0, n);
    return s + string(n - (int)s.size(), '0');
}

string truncatePrefixStr(const string& s, int n) {
    if (n <= 0) return "";
    if ((int)s.size() >= n) return s.substr(0, n);
    return s + string(n - (int)s.size(), '0');
}

class DeterministicRng32 {
public:
    int n = 624;
    int m = 397;
    uint32_t matrixA = 0x9908b0dfu;
    uint32_t upperMask = 0x80000000u;
    uint32_t lowerMask = 0x7fffffffu;
    vector<uint32_t> mt;
    int mti;

    explicit DeterministicRng32(const cpp_int& seedValue = 1) : mt(n, 0), mti(n + 1) { initializeSeed(seedValue); }

    void initializeSeed(cpp_int seedValue) {
        if (seedValue < 0) seedValue = -seedValue;
        vector<uint32_t> key;
        cpp_int x = seedValue;
        while (x > 0) {
            key.push_back(static_cast<uint32_t>((x & 0xFFFFFFFF).convert_to<uint64_t>()));
            x >>= 32;
        }
        if (key.empty()) key.push_back(0);
        expandSeed(key);
    }

    void initializeState(uint32_t s) {
        mt[0] = s & 0xFFFFFFFFu;
        for (int i = 1; i < n; ++i) mt[i] = (1812433253u * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFFu;
        mti = n;
    }

    void expandSeed(const vector<uint32_t>& initKey) {
        initializeState(19650218u);
        int i = 1;
        int j = 0;
        int keyLength = static_cast<int>(initKey.size());
        for (int k = max(n, keyLength); k > 0; --k) {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1664525u)) + initKey[j] + j;
            mt[i] &= 0xFFFFFFFFu;
            ++i; ++j;
            if (i >= n) { mt[0] = mt[n - 1]; i = 1; }
            if (j >= keyLength) j = 0;
        }
        for (int k = n - 1; k > 0; --k) {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1566083941u)) - i;
            mt[i] &= 0xFFFFFFFFu;
            ++i;
            if (i >= n) { mt[0] = mt[n - 1]; i = 1; }
        }
        mt[0] = 0x80000000u;
        mti = n;
    }

    uint32_t generateWord() {
        if (mti >= n) {
            uint32_t y;
            uint32_t mag01[2] = {0u, matrixA};
            for (int kk = 0; kk < n - m; ++kk) {
                y = (mt[kk] & upperMask) | (mt[kk + 1] & lowerMask);
                mt[kk] = mt[kk + m] ^ (y >> 1) ^ mag01[y & 1u];
            }
            for (int kk = n - m; kk < n - 1; ++kk) {
                y = (mt[kk] & upperMask) | (mt[kk + 1] & lowerMask);
                mt[kk] = mt[kk + (m - n)] ^ (y >> 1) ^ mag01[y & 1u];
            }
            y = (mt[n - 1] & upperMask) | (mt[0] & lowerMask);
            mt[n - 1] = mt[m - 1] ^ (y >> 1) ^ mag01[y & 1u];
            mti = 0;
        }
        uint32_t y = mt[mti++];
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680u;
        y ^= (y << 15) & 0xefc60000u;
        y ^= (y >> 18);
        return y & 0xFFFFFFFFu;
    }

    cpp_int generateBits(int k) {
        if (k <= 0) return 0;
        int words = (k + 31) / 32;
        cpp_int x = 0;
        for (int i = 0; i < words; ++i) x = (x << 32) | generateWord();
        int extra = words * 32 - k;
        if (extra) x >>= extra;
        return x;
    }

    cpp_int boundValue(const cpp_int& nVal) {
        if (nVal <= 0) throw runtime_error("n must be > 0");
        cpp_int t = nVal - 1;
        int k = 0;
        while (t > 0) { ++k; t >>= 1; }
        if (k <= 0) k = 1;
        while (true) {
            cpp_int r = generateBits(k);
            if (r < nVal) return r;
        }
    }

    cpp_int randint(const cpp_int& a, const cpp_int& b) {
        if (a > b) throw runtime_error("a must be <= b");
        return a + boundValue(b - a + 1);
    }

    template <typename T>
    void shuffle(vector<T>& arr) {
        for (int i = static_cast<int>(arr.size()) - 1; i > 0; --i) {
            int j = boundValue(i + 1).convert_to<int>();
            swap(arr[i], arr[j]);
        }
    }
};

vector<uint32_t> computeRadixDigits(cpp_int val, int b) {
    if (val == 0) return {0};
    if (val < 0) throw runtime_error("negative not supported in radix digits");
    vector<uint32_t> out;
    while (val > 0) {
        cpp_int rem = val % b;
        val /= b;
        out.push_back(rem.convert_to<uint32_t>());
    }
    reverse(out.begin(), out.end());
    return out;
}

cpp_int decodeRadixStream(const vector<uint32_t>& parts, int b) {
    cpp_int res = 0;
    for (uint32_t p : parts) res = res * b + p;
    return res;
}

string encodeRadix(cpp_int val, int b, size_t padTo, const string& charset) {
    string out(padTo, charset[0]);
    for (size_t i = 0; i < padTo; ++i) {
        cpp_int rem = val % b;
        val /= b;
        out[padTo - 1 - i] = charset[rem.convert_to<unsigned long long>()];
    }
    return out;
}

string encodeShift(const cpp_int& d, int b) {
    string c = deriveCharset(b);
    if (b == 1) return string((d + 1).convert_to<size_t>(), c[0]);
    cpp_int target = d * (b - 1) + b;
    size_t n = 0;
    cpp_int curBn = 1;
    vector<pair<size_t, cpp_int>> powers = {{1, cpp_int(b)}};
    while (powers.back().second <= target) powers.push_back({powers.back().first * 2, powers.back().second * powers.back().second});
    for (auto it = powers.rbegin(); it != powers.rend(); ++it) {
        if (curBn * it->second <= target) { curBn *= it->second; n += it->first; }
    }
    cpp_int geomSum = n > 0 ? (powInt(b, n) - b) / (b - 1) : 0;
    cpp_int r = d - geomSum;
    return n == 0 ? "" : encodeRadix(r, b, n, c);
}

cpp_int decodeShift(const string& c, int b) {
    const string& s = c;
    size_t l = s.size();
    if (b == 10) {
        static unordered_map<size_t, cpp_int> geom10;
        auto it = geom10.find(l);
        if (it == geom10.end()) it = geom10.emplace(l, l > 1 ? (powInt(10, l) - 10) / 9 : cpp_int(0)).first;
        return parseDec(s) + it->second;
    }
    if (b == 16) {
        static unordered_map<size_t, cpp_int> geom16;
        auto it = geom16.find(l);
        if (it == geom16.end()) it = geom16.emplace(l, l > 1 ? (powInt(16, l) - 16) / 15 : cpp_int(0)).first;
        cpp_int v = 0;
        for (char ch : s) v = (v << 4) + hexNibble(ch);
        return v + it->second;
    }
    static unordered_map<int, array<int, 256>> cache;
    auto itCache = cache.find(b);
    if (itCache == cache.end()) {
        array<int, 256> arr{}; arr.fill(-1);
        string chars = deriveCharset(b);
        for (int i = 0; i < b; ++i) arr[static_cast<unsigned char>(chars[i])] = i;
        itCache = cache.emplace(b, arr).first;
    }
    const auto& charMap = itCache->second;
    cpp_int v = 0;
    for (unsigned char ch : s) v = v * b + charMap[ch];
    cpp_int geomSum = (b > 1 && l > 1) ? (powInt(b, l) - b) / (b - 1) : cpp_int(0);
    return v + geomSum;
}

string generateKeystream(const cpp_int& s, int n) {
    DeterministicRng32 r(s);
    string out; out.reserve(n);
    for (int i = 0; i < n; ++i) out.push_back(char('0' + r.randint(0, 8).convert_to<int>()));
    return out;
}

string diffuseSequence(const string& s, const cpp_int& c) {
    DeterministicRng32 r(c);
    string out; out.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        int mask = r.randint(0, 8).convert_to<int>();
        out[i] = char((((s[i] - '0') + mask) % 10) + '0');
    }
    return out;
}

string permutePrefix(const string& s) {
    string mid = s.substr(2, 3);
    reverse(mid.begin(), mid.end());
    return s.substr(5) + mid + s.substr(0, 2);
}

string permuteSuffix(const string& s) {
    string mid = s.substr(s.size() - 5, 3);
    reverse(mid.begin(), mid.end());
    return s.substr(s.size() - 2) + mid + s.substr(0, s.size() - 5);
}

cpp_int distributeBits(const cpp_int& s, int f = 4) {
    string bitstream = dropPrefixBit(s);
    int width = static_cast<int>(bitstream.size());
    int rem = width % f;
    string out; out.reserve(bitstream.size() + 1); out.push_back('1');
    int stop = width - rem;
    for (int idx = 0; idx < stop; idx += f) {
        string lane = bitstream.substr(idx, f);
        reverse(lane.begin(), lane.end());
        out += lane;
    }
    if (rem) out.append(bitstream, stop, rem);
    return parseBits(out);
}

cpp_int diffuseBits(const cpp_int& s, const string& k) {
    string bitstream = dropPrefixBit(s);
    string keyText;
    for (char ch : k) if (ch != '0') keyText.push_back(ch);
    string out; out.reserve(bitstream.size() + 1); out.push_back('1');
    if (keyText.empty()) {
        out.append(bitstream.rbegin(), bitstream.rend());
        return parseBits(out);
    }
    vector<int> stride;
    for (char ch : keyText) stride.push_back((ch - '0') + 1);
    int pos = 0, turn = 0, width = static_cast<int>(bitstream.size());
    while (pos < width) {
        int step = stride[turn % static_cast<int>(stride.size())];
        int end = min(width, pos + step);
        string lane = bitstream.substr(pos, end - pos);
        reverse(lane.begin(), lane.end());
        out += lane;
        pos = end; ++turn;
    }
    return parseBits(out);
}

cpp_int distributeRadix(const cpp_int& n, const cpp_int& k, int b = 8, int y = 1) {
    int seedBase = 1 << 16;
    vector<uint32_t> stateDigits = computeRadixDigits(n, b);
    vector<uint32_t> schedule;
    for (uint32_t x : computeRadixDigits(k, seedBase)) if (2 <= static_cast<int>(to_string(x).size()) && static_cast<int>(to_string(x).size()) <= 10) schedule.push_back(x);
    if (schedule.empty()) schedule.push_back(((k % (seedBase - 2)) + 2).convert_to<uint32_t>());
    size_t limit = (stateDigits.size() + 2) * 40;
    size_t need = y == 1 ? stateDigits.size() + 1 : stateDigits.size();
    size_t loops = 0;
    while (schedule.size() < need) {
        cpp_int nextSeed = cpp_int(schedule.back()) + seedBase;
        for (uint32_t x : computeRadixDigits(nextSeed, seedBase)) if (2 <= static_cast<int>(to_string(x).size()) && static_cast<int>(to_string(x).size()) <= 10) schedule.push_back(x);
        ++loops;
        if (loops > limit) break;
    }
    while (schedule.size() < need) schedule.push_back(schedule.back());
    if (y == 1) {
        uint32_t guard = (1u + uint32_t(b) - (schedule[0] % uint32_t(b))) % uint32_t(b);
        vector<uint32_t> mixed; mixed.reserve(stateDigits.size() + 1);
        mixed.push_back(guard);
        mixed.insert(mixed.end(), stateDigits.begin(), stateDigits.end());
        for (size_t i = 0; i < mixed.size(); ++i) mixed[i] = (mixed[i] + (schedule[i] % uint32_t(b))) % uint32_t(b);
        return decodeRadixStream(mixed, b);
    }
    vector<uint32_t> mixed = stateDigits;
    for (size_t i = 0; i < mixed.size(); ++i) mixed[i] = (mixed[i] + uint32_t(b) - (schedule[i] % uint32_t(b))) % uint32_t(b);
    return mixed.size() <= 1 ? cpp_int(0) : decodeRadixStream(vector<uint32_t>(mixed.begin() + 1, mixed.end()), b);
}

int decodeDigit(char ch) { return ch - '0'; }

const array<array<uint64_t, 10>, 10>& computePiMatrix() {
    static const array<array<uint64_t, 10>, 10> box = {{
        {{14159265358979312ULL, 5707963267948966ULL, 4719755119659763ULL, 7853981633974483ULL, 6283185307179586ULL, 5235987755982988ULL, 4487989505128276ULL, 39269908169872414ULL, 3490658503988659ULL, 3141592653589793ULL}},
        {{5707963267948966ULL, 7853981633974483ULL, 5235987755982988ULL, 39269908169872414ULL, 3141592653589793ULL, 2617993877991494ULL, 2243994752564138ULL, 19634954084936207ULL, 17453292519943295ULL, 15707963267948966ULL}},
        {{4719755119659763ULL, 5235987755982988ULL, 3490658503988659ULL, 2617993877991494ULL, 20943951023931953ULL, 17453292519943295ULL, 14959965017094254ULL, 1308996938995747ULL, 11635528346628864ULL, 10471975511965977ULL}},
        {{7853981633974483ULL, 39269908169872414ULL, 2617993877991494ULL, 19634954084936207ULL, 15707963267948966ULL, 1308996938995747ULL, 1121997376282069ULL, 9817477042468103ULL, 8726646259971647ULL, 7853981633974483ULL}},
        {{6283185307179586ULL, 3141592653589793ULL, 20943951023931953ULL, 15707963267948966ULL, 12566370614359174ULL, 10471975511965977ULL, 8975979010256552ULL, 7853981633974483ULL, 6981317007977318ULL, 6283185307179587ULL}},
        {{5235987755982988ULL, 2617993877991494ULL, 17453292519943295ULL, 1308996938995747ULL, 10471975511965977ULL, 8726646259971647ULL, 7479982508547127ULL, 6544984694978735ULL, 5817764173314432ULL, 5235987755982988ULL}},
        {{4487989505128276ULL, 2243994752564138ULL, 14959965017094254ULL, 1121997376282069ULL, 8975979010256552ULL, 7479982508547127ULL, 641141357875468ULL, 5609986881410345ULL, 49866550056980846ULL, 4487989505128276ULL}},
        {{39269908169872414ULL, 19634954084936207ULL, 1308996938995747ULL, 9817477042468103ULL, 7853981633974483ULL, 6544984694978735ULL, 5609986881410345ULL, 4908738521234052ULL, 4363323129985824ULL, 39269908169872414ULL}},
        {{3490658503988659ULL, 17453292519943295ULL, 11635528346628864ULL, 8726646259971647ULL, 6981317007977318ULL, 5817764173314432ULL, 49866550056980846ULL, 4363323129985824ULL, 38785094488762877ULL, 3490658503988659ULL}},
        {{3141592653589793ULL, 15707963267948966ULL, 10471975511965977ULL, 7853981633974483ULL, 6283185307179587ULL, 5235987755982988ULL, 4487989505128276ULL, 39269908169872414ULL, 3490658503988659ULL, 31415926535897934ULL}}
    }};
    return box;
}

string prefixProduct(const string& n, const string& m, size_t p) { return decStr(parseDec(n) * parseDec(m)).substr(0, p); }
string biasTransform(const string& n, size_t p) {
    int seed = decodeDigit(n[0]);
    string out; out.reserve(p);
    for (size_t i = 0; i < p; ++i) out.push_back(char((((decodeDigit(n[i % n.size()]) + seed) % 10) + 48)));
    return out;
}
string prefixSquare(const string& n, const string&, size_t p) {
    size_t take = 3 % n.size();
    string left = n.substr(0, take);
    return decStr(parseDec(n) * parseDec(left)).substr(0, p);
}
string digitProduct(const string& n, const string& m, size_t p) {
    string out;
    size_t i = 0;
    while (out.size() < p) {
        int a = decodeDigit(n[i % n.size()]);
        int b = decodeDigit(m[i % m.size()]);
        out += to_string(abs(a * b));
        ++i;
    }
    return out.substr(0, p);
}
string integratePi(const string& n, size_t p) {
    const auto& box = computePiMatrix();
    cpp_int acc = 0;
    for (size_t i = 0; i < p; ++i) acc += box[decodeDigit(n[i % n.size()])][decodeDigit(n[(i + 1) % n.size()])];
    string out = decStr(acc);
    return out.size() <= p ? out : out.substr(out.size() - p);
}
string executeCascade(const string& state, const string& key, size_t width) {
    return prefixProduct(biasTransform(prefixSquare(digitProduct(integratePi(state, width), key, width), key, width), width), key, width);
}

string processKey(const cpp_int& nIn, cpp_int mIn = 0) {
    string state = decStr(nIn);
    string key = mIn == 0 ? state : decStr(mIn);
    size_t width = state.size();
    int seed = state[0] - '0';
    int tap = key.size() > static_cast<size_t>(seed) ? state[(key[seed] - '0') % width] - '0' : state.back() - '0';
    int routeA = (seed + tap) % 6;
    int routeB = (seed - tap) % 6; if (routeB < 0) routeB += 6;
    state = routeA == 0 ? prefixProduct(state, key, width) : routeA == 1 ? biasTransform(state, width) : routeA == 2 ? prefixSquare(state, key, width) : routeA == 3 ? digitProduct(state, key, width) : routeA == 4 ? integratePi(state, width) : executeCascade(state, key, width);
    state = routeB == 0 ? prefixSquare(state, key, width) : routeB == 1 ? digitProduct(state, key, width) : routeB == 2 ? executeCascade(state, key, width) : routeB == 3 ? biasTransform(state, width) : routeB == 4 ? prefixProduct(state, key, width) : executeCascade(state, key, width);
    char hi = '2', lo = '3';
    for (char ch : state) if (isdigit(static_cast<unsigned char>(ch)) && ch != '0') { hi = ch; break; }
    for (size_t i = 1; i < state.size(); ++i) if (isdigit(static_cast<unsigned char>(state[i])) && state[i] != '0') { lo = state[i]; break; }
    state = decStr(distributeBits(distributeBits(parseDec(state) + parseDec(permuteSuffix(state)))));
    state = decStr(decodeShift(permutePrefix(state), 10));
    cpp_int mask = parseDec(string() + hi + lo + string(width >= 2 ? width - 2 : 0, '0'));
    string out = decStr(parseDec(state) + mask + parseDec(key));
    return out.size() <= width ? out : out.substr(out.size() - width);
}

int deriveBaseFactor(const string& hex64) {
    string x = lowerStr(hex64);
    if (x.size() < 64) x = string(64 - x.size(), '0') + x;
    if (x.size() > 64) x = x.substr(x.size() - 64);
    string s4 = decStr(parseStdBase(x.substr(0, 4), 16) + parseStdBase(x.substr(x.size() - 4), 16));
    while (s4.size() > 1 && s4[0] == '0') s4.erase(s4.begin());
    if (s4.empty()) s4 = "0";
    if (s4.size() > 4) s4 = s4.substr(0, 4);
    int n = stoi(s4);
    if (n < 4096) return n;
    if (n % 2 == 0) return stoi(s4.substr(0, s4.size() - 1)) + ((s4.size() > 1 && s4[s4.size() - 2] == '0') ? 100 : 0);
    return stoi(s4.substr(1)) + ((s4.size() > 1 && s4[1] == '0') ? 100 : 0);
}

cpp_int encodeSentinel(const vector<uint8_t>& raw) {
    cpp_int out = 1;
    for (uint8_t x : raw) { out <<= 8; out += x; }
    return out;
}
cpp_int encodeTextBlock(const string& t) { return encodeSentinel(encodeUtf16Le(t)); }

string fold64(const string& h) {
    auto rot = [](uint64_t x, int r) -> uint64_t { return (x << r) | (x >> (64 - r)); };
    auto mix = [](uint64_t x) -> uint64_t {
        x ^= x >> 31; x *= 0x7FB5D329728EA185ULL; x ^= x >> 27; x *= 0x81DADEF4BC2DD44DULL; x ^= x >> 33; x *= 0xD6E8FEB86659FD93ULL; x ^= x >> 29; return x;
    };
    auto word = [](const vector<uint8_t>& b, size_t i) -> uint64_t {
        return uint64_t(b[i]) | (uint64_t(b[i + 1]) << 8) | (uint64_t(b[i + 2]) << 16) | (uint64_t(b[i + 3]) << 24) | (uint64_t(b[i + 4]) << 32) | (uint64_t(b[i + 5]) << 40) | (uint64_t(b[i + 6]) << 48) | (uint64_t(b[i + 7]) << 56);
    };
    vector<uint8_t> data(h.begin(), h.end());
    uint64_t n = static_cast<uint64_t>(data.size());
    uint64_t bitLen = n * 8ULL;
    data.push_back(0x80);
    while (data.size() % 128 != 112) data.push_back(0);
    uint64_t lenA = mix(bitLen ^ n ^ 0x9E3779B97F4A7C15ULL);
    uint64_t lenB = mix((bitLen << 1) ^ n ^ 0xC2B2AE3D27D4EB4FULL);
    for (int i = 0; i < 8; ++i) data.push_back(uint8_t((bitLen >> (8 * i)) & 0xFF));
    for (int i = 0; i < 8; ++i) data.push_back(uint8_t((lenA >> (8 * i)) & 0xFF));
    for (int i = 0; i < 8; ++i) data.push_back(uint8_t((lenB >> (8 * i)) & 0xFF));
    while (data.size() % 128 != 0) data.push_back(0);
    uint64_t a = 0x243F6A8885A308D3ULL ^ mix(bitLen ^ 0x01ULL);
    uint64_t b = 0x13198A2E03707344ULL ^ mix(bitLen ^ 0x02ULL);
    uint64_t c = 0xA4093822299F31D0ULL ^ mix(bitLen ^ 0x03ULL);
    uint64_t d = 0x082EFA98EC4E6C89ULL ^ mix(bitLen ^ 0x04ULL);
    uint64_t e = 0x452821E638D01377ULL ^ mix(bitLen ^ 0x05ULL);
    uint64_t f = 0xBE5466CF34E90C6CULL ^ mix(bitLen ^ 0x06ULL);
    uint64_t g = 0xC0AC29B7C97C50DDULL ^ mix(bitLen ^ 0x07ULL);
    uint64_t j = 0x3F84D5B5B5470917ULL ^ mix(bitLen ^ 0x08ULL);
    for (size_t off = 0; off < data.size(); off += 128) {
        uint64_t x0 = word(data, off + 0), x1 = word(data, off + 8), x2 = word(data, off + 16), x3 = word(data, off + 24);
        uint64_t x4 = word(data, off + 32), x5 = word(data, off + 40), x6 = word(data, off + 48), x7 = word(data, off + 56);
        uint64_t x8 = word(data, off + 64), x9 = word(data, off + 72), x10 = word(data, off + 80), x11 = word(data, off + 88);
        uint64_t x12 = word(data, off + 96), x13 = word(data, off + 104), x14 = word(data, off + 112), x15 = word(data, off + 120);
        uint64_t w0 = mix(x0 ^ a ^ x8 ^ 0x9E3779B97F4A7C15ULL), w1 = mix(x1 ^ b ^ x9 ^ 0xC2B2AE3D27D4EB4FULL), w2 = mix(x2 ^ c ^ x10 ^ 0x165667B19E3779F9ULL), w3 = mix(x3 ^ d ^ x11 ^ 0x85EBCA77C2B2AE63ULL), w4 = mix(x4 ^ e ^ x12 ^ 0x27D4EB2F165667C5ULL), w5 = mix(x5 ^ f ^ x13 ^ 0x94D049BB133111EBULL), w6 = mix(x6 ^ g ^ x14 ^ 0xD6E8FEB86659FD93ULL), w7 = mix(x7 ^ j ^ x15 ^ 0xA5A3564E27F8862DULL);
        for (int round = 0; round < 12; ++round) {
            uint64_t t0 = mix(a + w0 + rot(e ^ w4, 17) + rot(f ^ w5, 9));
            uint64_t t1 = mix(b + w1 + rot(f ^ w5, 29) + rot(g ^ w6, 21));
            uint64_t t2 = mix(c + w2 + rot(g ^ w6, 41) + rot(j ^ w7, 33));
            uint64_t t3 = mix(d + w3 + rot(j ^ w7, 11) + rot(a ^ w0, 45));
            uint64_t t4 = mix(e + w4 + rot(a ^ w0, 23) + rot(b ^ w1, 37));
            uint64_t t5 = mix(f + w5 + rot(b ^ w1, 31) + rot(c ^ w2, 49));
            uint64_t t6 = mix(g + w6 + rot(c ^ w2, 13) + rot(d ^ w3, 57));
            uint64_t t7 = mix(j + w7 + rot(d ^ w3, 27) + rot(e ^ w4, 39));
            a = mix(t0 ^ rot(t3, 7) ^ w1); b = mix(t1 ^ rot(t4, 11) ^ w2); c = mix(t2 ^ rot(t5, 19) ^ w3); d = mix(t3 ^ rot(t6, 23) ^ w4); e = mix(t4 ^ rot(t7, 31) ^ w5); f = mix(t5 ^ rot(t0, 37) ^ w6); g = mix(t6 ^ rot(t1, 43) ^ w7); j = mix(t7 ^ rot(t2, 53) ^ w0);
            w0 = mix(w0 ^ a ^ rot(w4, 9)); w1 = mix(w1 ^ b ^ rot(w5, 13)); w2 = mix(w2 ^ c ^ rot(w6, 17)); w3 = mix(w3 ^ d ^ rot(w7, 21)); w4 = mix(w4 ^ e ^ rot(w0, 25)); w5 = mix(w5 ^ f ^ rot(w1, 29)); w6 = mix(w6 ^ g ^ rot(w2, 33)); w7 = mix(w7 ^ j ^ rot(w3, 37));
            uint64_t oa = a, ob = b, oc = c, od = d, oe = e, of = f, og = g, oj = j;
            a = oc; c = oe; e = og; g = oa; b = of; d = ob; f = oj; j = od;
        }
        a = mix(a ^ x0 ^ x9 ^ w2); b = mix(b ^ x1 ^ x10 ^ w3); c = mix(c ^ x2 ^ x11 ^ w4); d = mix(d ^ x3 ^ x12 ^ w5); e = mix(e ^ x4 ^ x13 ^ w6); f = mix(f ^ x5 ^ x14 ^ w7); g = mix(g ^ x6 ^ x15 ^ w0); j = mix(j ^ x7 ^ x8 ^ w1);
    }
    uint64_t p = mix(a ^ c ^ e ^ g ^ 0x243F6A8885A308D3ULL), q = mix(b ^ d ^ f ^ j ^ 0x13198A2E03707344ULL), r = mix(a ^ b ^ e ^ f ^ 0xA4093822299F31D0ULL), t = mix(c ^ d ^ g ^ j ^ 0x082EFA98EC4E6C89ULL);
    p = mix(p ^ rot(q, 17) ^ rot(r, 31)); q = mix(q ^ rot(r, 23) ^ rot(t, 41)); r = mix(r ^ rot(t, 29) ^ rot(p, 37)); t = mix(t ^ rot(p, 13) ^ rot(q, 47));
    stringstream ss; ss << hex << nouppercase << setfill('0') << setw(16) << p << setw(16) << q << setw(16) << r << setw(16) << t;
    return lowerStr(ss.str());
}

pair<string, int> computeBound(const string& hexStr) {
    string h = lowerStr(hexStr); if (h.empty()) h = "0";
    cpp_int f = parseStdBase(h.size() >= 4 ? h.substr(0, 4) : h, 16);
    cpp_int l = parseStdBase(h.size() >= 4 ? h.substr(h.size() - 4) : h, 16);
    int seedVal = static_cast<int>(((f >> 8) ^ (l & 0xFF) ^ (f & 0xFF) ^ (l >> 8)).convert_to<uint64_t>() & 0xFF);
    string h2 = (h.size() & 1) ? ("0" + h) : h;
    string mh; mh.reserve(h2.size());
    for (size_t i = 0; i < h2.size(); i += 2) appendHexByte(mh, static_cast<uint8_t>((hexPairValue(h2, i) - seedVal) & 0xFF));
    mh = encodeHex(parseStdBase(mh, 16) + parseStdBase(h, 16));
    cpp_int baseParam = parseStdBase(mh.size() >= 4 ? mh.substr(0, 4) : mh, 16);
    cpp_int nVal = parseStdBase(mh, 16);
    cpp_int kVal = parseStdBase(mh.size() >= 4 ? mh.substr(mh.size() - 4) : mh, 16);
    cpp_int splitVal = distributeRadix(nVal, kVal, ((baseParam & 4096) + 64).convert_to<int>(), 1);
    string splitHex = encodeHex(splitVal);
    string s = fold64(h + mh + splitHex);
    return {s, deriveBaseFactor(s)};
}

string compressKey(cpp_int n, size_t width = 78) {
    while (true) {
        n = (n / 8) + parseDec(integratePi(decStr(n / 5), decStr(n).size()));
        string s = decStr(n);
        if (s.size() <= width) return s;
    }
}
string diffuseKey(const cpp_int& n) { return encodeShift(decodeShift(encodeHex(n), 16) + parseStdBase(encodeShift(n, 16), 16), 16); }

cpp_int validateState(cpp_int n, cpp_int i = 10) {
    if (n < 0 || i < 0) throw runtime_error("n and i must be >= 0");
    n += 32;
    size_t ln = decStr(n).size();
    cpp_int ten79 = powInt(10, 79);
    while (n < ten79) { n *= 3; n = n + i; i = i + i; }
    i = cpp_int(10) * (cpp_int(1) << 163);
    n = parseDec(decStr(n) + string(16, '0') + to_string(ln));
    for (int k = 0; k < 8; ++k) { n *= 3; n = n + i; i = i + i; }
    n = parseDec(decStr(n * i) + string(8, '0')) + i;
    string s = decStr(n);
    cpp_int chunkBase = powInt(10, 80), packBase = powInt(10, 82), packed = static_cast<unsigned long long>(s.size()) + 1;
    for (size_t j = 0; j < s.size(); j += 80) {
        string chunk = s.substr(j, 80);
        packed = packed * packBase + (cpp_int(chunk.size()) * chunkBase) + parseDec(chunk);
    }
    string left = permutePrefix(decStr(distributeBits(packed)));
    string right = processKey(packed);
    string leftLen = to_string(left.size()); if (leftLen.size() < 6) leftLen = string(6 - leftLen.size(), '0') + leftLen;
    cpp_int mix = parseDec(string("1") + leftLen + left + right);
    return diffuseBits(mix, decStr(packed));
}

string deriveKeyState(const cpp_int& n) {
    cpp_int seedState = validateState(n + 90, (n % 7) + 1);
    string compactState = compressKey(seedState, 79);
    string diffusedState = diffuseSequence(compactState, n);
    cpp_int decodedState = decodeShift(diffusedState, 10);
    return diffuseKey(decodedState);
}

pair<string, int> computeKeyDigest(const cpp_int& n) {
    string chainA = deriveKeyState(n);
    cpp_int a = parseStdBase(chainA + encodeHex(n), 16);
    string chainB = deriveKeyState(a);
    return computeBound(chainB);
}

string generateSeedSource() {
    string chars = deriveCharset(62);
    vector<uint8_t> raw = secureRandomBytes(32);
    cpp_int seedVal = bytesToInt(raw) ^ cpp_int(chrono::duration_cast<chrono::nanoseconds>(chrono::high_resolution_clock::now().time_since_epoch()).count());
    DeterministicRng32 r(seedVal);
    int ln = r.randint(64, 256).convert_to<int>();
    vector<char> s; s.reserve(ln);
    for (int i = 0; i < ln; ++i) s.push_back(chars[r.boundValue(62).convert_to<int>()]);
    r.shuffle(s);
    return string(s.begin(), s.end());
}

vector<uint8_t> normalizeSeedBytes(const string& x) { return encodeUtf16Le(x); }
vector<uint8_t> normalizeSeedBytes(const cpp_int& x) { return encodeUtf16Le(decStr(x)); }
vector<uint8_t> normalizeSeedBytes(const vector<uint8_t>& x) { return x; }
cpp_int normalizeSeedInput(const string& x) { return encodeSentinel(normalizeSeedBytes(x)); }
cpp_int normalizeSeedInput(const cpp_int& x) { return encodeSentinel(normalizeSeedBytes(x)); }
cpp_int normalizeSeedInput(const vector<uint8_t>& x) { return encodeSentinel(x); }

vector<uint8_t> diffuseBlocks(const vector<uint8_t>& data, int v = 1, int cols = 73, int rows = 72) {
    (void)v;
    vector<uint8_t> raw = data;
    cols = int(cols); rows = int(rows);
    if (cols < 1 || rows < 1) throw runtime_error("cols and rows must be >= 1");
    const uint64_t mask = 0xFFFFFFFFFFFFFFFFULL;
    const int laneCount = cols;
    const size_t blockBytes = max<size_t>(1, static_cast<size_t>(((cols * rows) + 7) / 8));
    const size_t outLen = static_cast<size_t>(cols) * 5;
    auto rot = [&](uint64_t x, int r) -> uint64_t { x &= mask; r &= 63; return r == 0 ? x : ((x << r) | (x >> (64 - r))) & mask; };
    auto mix64 = [&](uint64_t x) -> uint64_t { x &= mask; x ^= x >> 30; x = (x * 0xBF58476D1CE4E5B9ULL) & mask; x ^= x >> 27; x = (x * 0x94D049BB133111EBULL) & mask; x ^= x >> 31; return x & mask; };
    auto h64 = [&](const string& x) -> uint64_t { string y = fold64(x); cpp_int z = parseStdBase(y, 16) & cpp_int(mask); return z.convert_to<uint64_t>(); };
    auto word64 = [&](const vector<uint8_t>& b, size_t i) -> uint64_t {
        uint64_t out = 0; size_t lim = min<size_t>(8, b.size() > i ? b.size() - i : 0);
        for (size_t j = 0; j < lim; ++j) out |= (uint64_t(b[i + j]) << (8 * j));
        return out;
    };
    auto runPass = [&](const vector<uint8_t>& srcIn, uint64_t seedA, uint64_t seedB) -> pair<size_t, vector<uint8_t>> {
        vector<uint8_t> src = srcIn;
        vector<uint64_t> state(laneCount, 0);
        for (int i = 0; i < laneCount; ++i) state[i] = mix64(seedA ^ ((uint64_t(i + 1) * 0x9E3779B185EBCA87ULL) & mask) ^ rot(seedB, (i % 31) + 1) ^ (uint64_t(src.size() + i) * 0xD6E8FEB86659FD93ULL));
        size_t blockCount = 0;
        for (size_t off = 0; off < src.size(); off += blockBytes) {
            vector<uint8_t> block(src.begin() + off, src.begin() + min(src.size(), off + blockBytes));
            size_t blockLen = block.size();
            uint64_t blockState = mix64(seedB ^ uint64_t(blockCount) ^ uint64_t(blockLen) ^ rot(state[blockCount % laneCount], ((blockCount % 29) + 1)));
            size_t wordCount = (blockLen + 7) / 8;
            for (size_t wIndex = 0; wIndex < wordCount; ++wIndex) {
                size_t pos = wIndex * 8; uint64_t word = word64(block, pos); size_t g = off + pos;
                int i = int((word + g + blockCount) % laneCount), j = int((i + 17 + (wIndex % 13)) % laneCount), k = int((uint64_t(i) * 7 + 29 + (word >> 11)) % laneCount);
                uint64_t a = state[i], b = state[j], c = state[k];
                uint64_t x = mix64(word ^ blockState ^ (uint64_t(g + 1) * 0x9E3779B185EBCA87ULL) ^ uint64_t(src.size()));
                state[i] = mix64((a + x + rot(b, 13) + rot(c, 29)) & mask);
                state[j] = mix64(b ^ x ^ rot(a, 17) ^ rot(c, 37));
                state[k] = mix64((c + x + rot(b, 43) + rot(a, 53) + uint64_t(wordCount) + uint64_t(wIndex)) & mask);
                blockState = mix64(blockState ^ x ^ state[i] ^ rot(state[j], 11) ^ rot(state[k], 23));
                if ((wIndex & 7ULL) == 7ULL) {
                    int t = int((i + j + k + int(wIndex)) % laneCount), u = (t + 31) % laneCount;
                    state[t] = mix64(state[t] ^ blockState ^ rot(state[u], 19) ^ (uint64_t(g + 1) * 0xD6E8FEB86659FD93ULL));
                    state[u] = mix64((state[u] + state[t] + rot(blockState, 27) + x) & mask);
                }
            }
            int p = int(blockCount % laneCount), q = (p + 23) % laneCount, r = (p + 47) % laneCount;
            uint64_t d = mix64(blockState ^ uint64_t(blockLen) ^ uint64_t(off) ^ uint64_t(src.size()));
            state[p] = mix64(state[p] ^ d ^ rot(blockState, 17));
            state[q] = mix64((state[q] + d + rot(state[p], 9) + uint64_t(src.size()) + uint64_t(blockCount)) & mask);
            state[r] = mix64(state[r] ^ rot(d, 33) ^ state[p] ^ state[q] ^ uint64_t(blockLen));
            ++blockCount;
        }
        int rounds = max(6, rows / 12);
        for (int rnd = 0; rnd < rounds; ++rnd) {
            uint64_t seed = mix64(seedA ^ seedB ^ uint64_t(rnd) ^ uint64_t(src.size()) ^ state[rnd % laneCount]);
            uint64_t prev = state.back();
            for (int i = 0; i < laneCount; ++i) {
                uint64_t cur = state[i], nxt = state[(i + 1) % laneCount], far = state[(i * 7 + rnd + 3) % laneCount];
                uint64_t m = mix64(cur ^ rot(nxt, ((i + rnd) % 31) + 1) ^ rot(far, ((i * 3 + rnd) % 31) + 1) ^ prev ^ seed ^ uint64_t(i) ^ uint64_t(src.size()));
                state[i] = mix64((cur + m + rot(prev, 13) + rot(seed, 1 + ((i + rnd) % 31))) & mask);
                prev = cur;
            }
            int pivot = rnd % laneCount;
            state[pivot] = mix64(state[pivot] ^ seed ^ rot(state[(pivot + 19) % laneCount], 7));
            state[(pivot + 37) % laneCount] = mix64((state[(pivot + 37) % laneCount] + rot(seed, 23) + state[pivot]) & mask);
        }
        vector<uint8_t> out(outLen, 0);
        uint64_t seed = mix64(seedA ^ seedB ^ uint64_t(src.size()) ^ uint64_t(blockCount));
        size_t pos = 0;
        for (int phase = 0; phase < 5; ++phase) {
            for (int i = 0; i < laneCount; ++i) {
                uint64_t a = state[i], b = state[(i + phase + 1) % laneCount], c = state[(i * 11 + phase + 7) % laneCount];
                uint64_t q = mix64(a ^ rot(b, ((phase + i) % 31) + 1) ^ rot(c, ((phase * 7 + i) % 31) + 1) ^ seed ^ (uint64_t(phase) << 8) ^ uint64_t(i));
                out[pos++] = uint8_t((q ^ (q >> 8) ^ (q >> 16) ^ (q >> 24)) & 0xFF);
                state[i] = mix64((a + q + rot(c, 17) + rot(seed, 1 + (i % 31))) & mask);
            }
            seed = mix64(seed ^ state[phase % laneCount] ^ rot(state[(phase * 11 + 3) % laneCount], 19));
        }
        return {blockCount, out};
    };
    size_t totalLen = raw.size();
    vector<uint8_t> head(raw.begin(), raw.begin() + min<size_t>(128, raw.size()));
    uint64_t seedA = mix64(uint64_t(totalLen) ^ uint64_t(cols) ^ (uint64_t(rows) << 32) ^ 0x243F6A8885A308D3ULL);
    uint64_t seedB = raw.empty() ? mix64(seedA ^ 0x13198A2E03707344ULL) : h64(bytesToHex(vector<uint8_t>(raw.begin(), raw.begin() + min<size_t>(256, raw.size()))) + "|" + bytesToHex(vector<uint8_t>(raw.end() - min<size_t>(256, raw.size()), raw.end())) + "|" + to_string(totalLen));
    auto passA = runPass(raw, seedA, seedB);
    vector<uint8_t> mixIn = passA.second;
    mixIn.insert(mixIn.end(), head.begin(), head.end());
    vector<uint8_t> arrA64(passA.second.begin(), passA.second.begin() + min<size_t>(64, passA.second.size()));
    uint64_t seedC = mix64(seedB ^ h64(bytesToHex(head) + "|" + bytesToHex(arrA64) + "|" + to_string(mixIn.size())));
    auto passB = runPass(mixIn, seedB, seedC);
    vector<uint8_t> merged(outLen, 0);
    uint64_t mergeSeed = mix64(seedA ^ seedB ^ seedC ^ uint64_t(mixIn.size()) ^ uint64_t(outLen));
    size_t headLen = head.size();
    for (size_t i = 0; i < outLen; ++i) {
        uint8_t a = passA.second[i], b = passB.second[i], c = headLen ? head[i % headLen] : uint8_t((i * 17 + totalLen) & 0xFF);
        uint64_t m = mix64(mergeSeed ^ uint64_t(a) ^ (uint64_t(b) << 8) ^ (uint64_t(c) << 16) ^ (uint64_t(i) << 24));
        merged[i] = uint8_t((uint64_t(a) ^ uint64_t(b) ^ uint64_t(c) ^ m ^ (m >> 8) ^ (m >> 16) ^ (m >> 24)) & 0xFF);
        mergeSeed = mix64(mergeSeed ^ m ^ uint64_t(a) ^ (uint64_t(b) << 8) ^ (uint64_t(c) << 16) ^ uint64_t(i));
    }
    return merged;
}

string computeKeyDigestStream(const vector<uint8_t>& raw, int directBits = 256, int laneBits = 336, int blockBytes = 4096) {
    (void)laneBits; (void)blockBytes;
    int directBytes = max(1, (int(directBits) + 7) / 8);
    if (int(raw.size()) <= directBytes) return lowerStr(computeKeyDigest(encodeSentinel(raw)).first);
    vector<uint8_t> diffused = diffuseBlocks(raw, 1);
    return lowerStr(computeKeyDigest(encodeSentinel(diffused)).first);
}
string computeKeyDigestFile(const string& path, int directBits = 256, int laneBits = 336, int blockBytes = 65536) {
    (void)laneBits; (void)blockBytes;
    vector<uint8_t> raw = readFileBytes(path);
    int directBytes = max(1, (int(directBits) + 7) / 8);
    if (int(raw.size()) <= directBytes) return lowerStr(computeKeyDigest(encodeSentinel(raw)).first);
    vector<uint8_t> diffused = diffuseBlocks(raw, 1);
    return lowerStr(computeKeyDigest(encodeSentinel(diffused)).first);
}

struct TraceState { cpp_int input, first, firstPad, second, third, packedLen, fourth; string left; cpp_int mix; string right; cpp_int value; };
TraceState traceWideState(const cpp_int& nIn, cpp_int i = 10) {
    if (nIn < 0 || i < 0) throw runtime_error("n and i must be >= 0");
    cpp_int n = nIn + 32, start = n; size_t ln = decStr(n).size(); cpp_int ten79 = powInt(10, 79);
    while (n < ten79) { n *= 3; n = n + i; i = i + i; }
    cpp_int first = n; i = cpp_int(10) * (cpp_int(1) << 163); n = parseDec(decStr(n) + string(16, '0') + to_string(ln)); cpp_int firstPad = n;
    for (int k = 0; k < 8; ++k) { n *= 3; n = n + i; i = i + i; }
    cpp_int second = n; n = parseDec(decStr(n * i) + string(8, '0')) + i; cpp_int third = n;
    string s = decStr(n); cpp_int chunkBase = powInt(10, 80), packBase = powInt(10, 82), packed = static_cast<unsigned long long>(s.size()) + 1;
    for (size_t j = 0; j < s.size(); j += 80) { string chunk = s.substr(j, 80); packed = packed * packBase + (cpp_int(chunk.size()) * chunkBase) + parseDec(chunk); }
    cpp_int packedLen = static_cast<unsigned long long>(s.size()), fourth = packed;
    string left = permutePrefix(decStr(distributeBits(fourth))), right = processKey(fourth);
    cpp_int mix = parseDec(string("1") + leftPad(static_cast<unsigned long long>(left.size()), 6) + left + right);
    cpp_int value = diffuseBits(mix, decStr(fourth));
    return {start, first, firstPad, second, third, packedLen, fourth, left, mix, right, value};
}

string bindState(const TraceState& trace, const string& modeId = "32") {
    vector<string> parts = { modeId, truncatePrefix(trace.input, 24), truncatePrefix(trace.first, 96), truncatePrefix(trace.firstPad, 96), truncatePrefix(trace.second, 96), truncatePrefix(trace.third, 96), truncatePrefix(trace.fourth, 96), truncatePrefixStr(trace.left, 96), truncatePrefix(trace.mix, 96), truncatePrefixStr(trace.right, 96), truncatePrefix(trace.value, 96) };
    string joined; for (size_t i = 0; i < parts.size(); ++i) { if (i) joined += "|"; joined += parts[i]; }
    string a = fold64(joined), b = computeBound(a).first, c = processKey(decodeShift(b, 16)), d = fold64(a + b + c + truncatePrefix(trace.packedLen, 8)), e = computeBound(d + a).first;
    return fold64(e + d + b + a);
}
string computeHex(const TraceState& trace, const string& modeId = "333", const string& seedHex = "") {
    string root = seedHex.empty() ? bindState(trace, modeId + "|BASE") : seedHex;
    string a = fold64(root + truncatePrefix(trace.value, 128)), b = computeBound(a).first, c = fold64(b + root + truncatePrefix(trace.mix, 128)), d = computeBound(c + a).first;
    return (c + d).substr(0, 64);
}
string scheduleText(const vector<tuple<int, char, int>>& sched) { string out; for (const auto& [pos, ch, val] : sched) { out += leftPad(pos, 2); out.push_back(ch); out += leftPad(val, 2); } return out; }
vector<tuple<int, char, int>> deriveInjection(const TraceState& trace, const string& baseHexStr, int count = 8, const string& modeId = "333", const string& seedHex = "") {
    if (count < 1 || count > 8) throw runtime_error("count must be in 1..8");
    int totalLen = 64 + count; string aux = deriveAuxCharset(); vector<int> avail(totalLen); for (int i = 0; i < totalLen; ++i) avail[i] = i; string state = seedHex.empty() ? bindState(trace, modeId + "|LOTTERY") : seedHex; vector<tuple<int, char, int>> sched;
    for (int i = 0; i < count; ++i) {
        string posSeed = fold64("POS|" + to_string(i) + "|" + state + "|" + truncatePrefixStr(trace.left, 96) + "|" + baseHexStr);
        string valSeed = fold64("VAL|" + to_string(i) + "|" + state + "|" + truncatePrefixStr(trace.right, 96) + "|" + baseHexStr);
        int pick = (decodeShift(posSeed, 16) % avail.size()).convert_to<int>(); int pos = avail[pick]; avail.erase(avail.begin() + pick);
        int val = (decodeShift(valSeed, 16) % aux.size()).convert_to<int>(); char ch = aux[val]; sched.push_back({pos, ch, val});
        state = fold64("ROUND|" + to_string(i) + "|" + state + "|" + to_string(pos) + "|" + to_string(val) + "|" + truncatePrefix(trace.mix, 96) + "|" + baseHexStr);
    }
    return sched;
}
string distributeSymbols(const string& baseHexStr, const vector<tuple<int, char, int>>& sched, int count = 8) {
    int totalLen = 64 + count; string out(totalLen, '\0'); for (const auto& [pos, ch, _] : sched) out[pos] = ch; int j = 0; for (int i = 0; i < totalLen; ++i) if (out[i] == '\0') out[i] = baseHexStr[j++]; return out;
}
string computeTraceExtended(const TraceState& trace, int count = 8) {
    string root = bindState(trace, "333|ROOT"), bodyB = computeHex(trace, "333|BASE", root); auto pepperB = deriveInjection(trace, bodyB, count, "333|LOTTERY", root); string raw = distributeSymbols(bodyB, pepperB, count); string rebound = fold64(root + raw + scheduleText(pepperB) + truncatePrefix(trace.first, 96)); string body = computeHex(trace, "333|BASE2", rebound); auto pepper = deriveInjection(trace, body, count, "333|LOTTERY2", rebound); return distributeSymbols(body, pepper, count);
}
string computeTraceDigest(const TraceState& trace) { string root = bindState(trace, "32|FINAL"), a = fold64(root + truncatePrefix(trace.value, 128)), b = lowerStr(computeBound(a).first), c = fold64(b + root + truncatePrefixStr(trace.right, 128)); return c.substr(0, 64); }

string generatePrimaryKey(int directBits = 256, int laneBits = 336, int blockBytes = 4096) { return computeKeyDigestStream(normalizeSeedBytes(generateSeedSource()), directBits, laneBits, blockBytes); }
string generatePrimaryKey(const string& x, int directBits = 256, int laneBits = 336, int blockBytes = 4096) { return computeKeyDigestStream(normalizeSeedBytes(x), directBits, laneBits, blockBytes); }
string generatePrimaryKey(const cpp_int& x, int directBits = 256, int laneBits = 336, int blockBytes = 4096) { return computeKeyDigestStream(normalizeSeedBytes(x), directBits, laneBits, blockBytes); }
string generateExtendedKey(int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096) {
    (void)laneBits; (void)blockBytes; vector<uint8_t> raw = normalizeSeedBytes(generateSeedSource()); int directBytes = max(1, (int(directBits) + 7) / 8); if (int(raw.size()) <= directBytes) return computeTraceExtended(traceWideState(encodeSentinel(raw)), count); vector<uint8_t> diffused = diffuseBlocks(raw, 1); return computeTraceExtended(traceWideState(encodeSentinel(diffused)), count);
}
string generateExtendedKey(const string& x, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096) {
    (void)laneBits; (void)blockBytes; vector<uint8_t> raw = normalizeSeedBytes(x); int directBytes = max(1, (int(directBits) + 7) / 8); if (int(raw.size()) <= directBytes) return computeTraceExtended(traceWideState(encodeSentinel(raw)), count); vector<uint8_t> diffused = diffuseBlocks(raw, 1); return computeTraceExtended(traceWideState(encodeSentinel(diffused)), count);
}
string generateExtendedKey(const cpp_int& x, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096) {
    (void)laneBits; (void)blockBytes; vector<uint8_t> raw = normalizeSeedBytes(x); int directBytes = max(1, (int(directBits) + 7) / 8); if (int(raw.size()) <= directBytes) return computeTraceExtended(traceWideState(encodeSentinel(raw)), count); vector<uint8_t> diffused = diffuseBlocks(raw, 1); return computeTraceExtended(traceWideState(encodeSentinel(diffused)), count);
}
string generateKey(int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096) { return mode == 0 ? generatePrimaryKey(directBits, laneBits, blockBytes) : generateExtendedKey(count, directBits, laneBits, blockBytes); }
string generateKey(const string& x, int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096) { return mode == 0 ? generatePrimaryKey(x, directBits, laneBits, blockBytes) : generateExtendedKey(x, count, directBits, laneBits, blockBytes); }
string generateKey(const cpp_int& x, int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096) { return mode == 0 ? generatePrimaryKey(x, directBits, laneBits, blockBytes) : generateExtendedKey(x, count, directBits, laneBits, blockBytes); }
string generateKeyFile(const string& path, int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 65536) {
    if (mode == 0) return computeKeyDigestFile(path, directBits, laneBits, blockBytes);
    vector<uint8_t> raw = readFileBytes(path); int directBytes = max(1, (int(directBits) + 7) / 8); if (int(raw.size()) <= directBytes) return computeTraceExtended(traceWideState(encodeSentinel(raw)), count); vector<uint8_t> diffused = diffuseBlocks(raw, 1); return computeTraceExtended(traceWideState(encodeSentinel(diffused)), count);
}

string trimStr(const string& s) { size_t a = 0, b = s.size(); while (a < b && isspace(static_cast<unsigned char>(s[a]))) ++a; while (b > a && isspace(static_cast<unsigned char>(s[b - 1]))) --b; return s.substr(a, b - a); }
bool isHex64(const string& k) { if (k.size() != 64) return false; for (char ch : k) if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false; return true; }
uint64_t diffuseWord64(uint64_t x) { x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL; x ^= x >> 27; x *= 0x94D049BB133111EBULL; x ^= x >> 31; return x; }
vector<uint8_t> cppIntToBytes(cpp_int n) { if (n < 0) throw runtime_error("negative integer to bytes"); if (n == 0) return {}; vector<uint8_t> out; while (n > 0) { out.push_back(static_cast<uint8_t>((n & 0xFF).convert_to<unsigned int>())); n >>= 8; } reverse(out.begin(), out.end()); return out; }
vector<uint8_t> decodeSentinelBytes(const cpp_int& n) { vector<uint8_t> b = cppIntToBytes(n); if (b.empty() || b[0] != 1) throw runtime_error("byte sentinel missing"); return vector<uint8_t>(b.begin() + 1, b.end()); }
vector<uint8_t> recoverSentinelBytes(const cpp_int& n) { vector<uint8_t> b = cppIntToBytes(n); if (b.empty()) return {}; if (b[0] == 1) return vector<uint8_t>(b.begin() + 1, b.end()); size_t i = 0; while (i < b.size() && b[i] == 0) ++i; if (i < b.size() && b[i] == 1) return vector<uint8_t>(b.begin() + i + 1, b.end()); if (b.size() > 1) return vector<uint8_t>(b.begin() + 1, b.end()); return {}; }
vector<vector<uint8_t>> splitByteBlocks(const vector<uint8_t>& b, int chunkSize = 2048) { if (chunkSize <= 0) throw runtime_error("chunkSize must be > 0"); if (b.empty()) return {{}}; vector<vector<uint8_t>> out; for (size_t i = 0; i < b.size(); i += static_cast<size_t>(chunkSize)) { size_t take = min(static_cast<size_t>(chunkSize), b.size() - i); out.emplace_back(b.begin() + i, b.begin() + i + take); } return out; }
bool verifyZlib(const vector<uint8_t>& b) { if (b.size() < 2) return false; uint8_t cmf = b[0], flg = b[1]; if ((cmf & 0x0F) != 8) return false; if ((cmf >> 4) > 7) return false; return (((int(cmf) << 8) + int(flg)) % 31) == 0; }

string decodeSafeText(vector<uint8_t> b) {
    if (b.size() & 1) b.pop_back();
    vector<uint16_t> units; units.reserve(b.size() / 2);
    for (size_t i = 0; i + 1 < b.size(); i += 2) units.push_back(uint16_t(b[i]) | (uint16_t(b[i + 1]) << 8));
    string out;
    for (size_t i = 0; i < units.size(); ++i) {
        uint16_t u = units[i];
        if (0xD800 <= u && u <= 0xDBFF) {
            if (i + 1 < units.size() && 0xDC00 <= units[i + 1] && units[i + 1] <= 0xDFFF) {
                uint32_t cp = 0x10000 + (((uint32_t(u) - 0xD800) << 10) | (uint32_t(units[i + 1]) - 0xDC00));
                appendUtf8(out, cp); ++i;
            } else appendUtf8(out, 0xFFFD);
        } else if (0xDC00 <= u && u <= 0xDFFF) appendUtf8(out, 0xFFFD);
        else appendUtf8(out, u);
    }
    return out;
}

string deriveSecureSeed() {
    vector<uint8_t> raw = secureRandomBytes(16);
    string s = decStr(bytesToInt(raw));
    if (s.size() < 39) s = string(39 - s.size(), '0') + s;
    return s;
}
string encodeSeed(const string& msgSeedDec) { string h = encodeHex(parseDec(msgSeedDec)); if (h.size() < 32) h = string(32 - h.size(), '0') + h; if (h.size() > 32) h = h.substr(h.size() - 32); return lowerStr(h); }
struct SeedState { string saltHex, nonceHex, ivHex; };
SeedState expandSeedState(const string& msgSeedDec) {
    string msgSeedHex = encodeSeed(msgSeedDec), a = fold64("WRAP|SEED|A|" + msgSeedHex), b = fold64("WRAP|SEED|B|" + a + msgSeedHex), c = fold64("WRAP|SEED|C|" + b + a + msgSeedHex);
    return { lowerStr(computeBound(a + b).first).substr(0, 32), lowerStr(computeBound(b + c).first).substr(0, 32), lowerStr(computeBound(c + a).first).substr(0, 32) };
}
string deriveWrapSeed() { return deriveSecureSeed(); }
string packPortableBytes(const vector<uint8_t>& b) { return encodeShift(encodeSentinel(b), 62); }
vector<uint8_t> unpackPortableBytes(const string& s) { return decodeSentinelBytes(decodeShift(s, 62)); }

string jsonEscape(const string& s) {
    string out; out.push_back('"');
    for (unsigned char ch : s) {
        switch (ch) {
            case '"': out += "\\\""; break; case '\\': out += "\\\\"; break; case '\b': out += "\\b"; break; case '\f': out += "\\f"; break; case '\n': out += "\\n"; break; case '\r': out += "\\r"; break; case '\t': out += "\\t"; break;
            default: if (ch < 0x20) { static const char* lut = "0123456789abcdef"; out += "\\u00"; out.push_back(lut[(ch >> 4) & 0xF]); out.push_back(lut[ch & 0xF]); } else out.push_back(static_cast<char>(ch));
        }
    }
    out.push_back('"'); return out;
}

struct JsonVal { enum Type { Str, Num, ArrNum } type = Str; string s; vector<string> arr; };
using JsonObj = map<string, JsonVal>;
string canonicalJson(const JsonObj& obj) {
    string out = "{"; bool first = true;
    for (const auto& kv : obj) {
        if (!first) out.push_back(','); first = false;
        out += jsonEscape(kv.first); out.push_back(':'); const JsonVal& v = kv.second;
        if (v.type == JsonVal::Str) out += jsonEscape(v.s); else if (v.type == JsonVal::Num) out += v.s; else { out.push_back('['); for (size_t i = 0; i < v.arr.size(); ++i) { if (i) out.push_back(','); out += v.arr[i]; } out.push_back(']'); }
    }
    out.push_back('}'); return out;
}
struct JsonParser {
    const string& s; size_t i = 0; JsonParser(const string& text) : s(text) {}
    void ws() { while (i < s.size() && isspace(static_cast<unsigned char>(s[i]))) ++i; }
    void need(char ch) { ws(); if (i >= s.size() || s[i] != ch) throw runtime_error("bad json"); ++i; }
    string parseString() {
        ws(); if (i >= s.size() || s[i] != '"') throw runtime_error("bad json string"); ++i; string out;
        while (i < s.size()) {
            char ch = s[i++]; if (ch == '"') return out;
            if (ch == '\\') {
                if (i >= s.size()) throw runtime_error("bad json escape"); char e = s[i++];
                switch (e) { case '"': out.push_back('"'); break; case '\\': out.push_back('\\'); break; case '/': out.push_back('/'); break; case 'b': out.push_back('\b'); break; case 'f': out.push_back('\f'); break; case 'n': out.push_back('\n'); break; case 'r': out.push_back('\r'); break; case 't': out.push_back('\t'); break; case 'u': if (i + 4 > s.size()) throw runtime_error("bad json unicode"); { string hx = s.substr(i, 4); i += 4; unsigned int code = parseStdBase(hx, 16).convert_to<unsigned int>(); appendUtf8(out, code); } break; default: throw runtime_error("bad json escape"); }
            } else out.push_back(ch);
        }
        throw runtime_error("unterminated json string");
    }
    string parseNumber() { ws(); size_t a = i; if (i < s.size() && s[i] == '-') ++i; if (i >= s.size() || !isdigit(static_cast<unsigned char>(s[i]))) throw runtime_error("bad json number"); while (i < s.size() && isdigit(static_cast<unsigned char>(s[i]))) ++i; return s.substr(a, i - a); }
    vector<string> parseNumArray() { need('['); vector<string> out; ws(); if (i < s.size() && s[i] == ']') { ++i; return out; } while (true) { out.push_back(parseNumber()); ws(); if (i >= s.size()) throw runtime_error("bad json array"); if (s[i] == ']') { ++i; break; } if (s[i] != ',') throw runtime_error("bad json array"); ++i; } return out; }
    JsonObj parseObject() {
        JsonObj obj; need('{'); ws(); if (i < s.size() && s[i] == '}') { ++i; return obj; }
        while (true) {
            string k = parseString(); need(':'); ws(); JsonVal v;
            if (i < s.size() && s[i] == '"') { v.type = JsonVal::Str; v.s = parseString(); }
            else if (i < s.size() && s[i] == '[') { v.type = JsonVal::ArrNum; v.arr = parseNumArray(); }
            else { v.type = JsonVal::Num; v.s = parseNumber(); }
            obj[k] = v; ws(); if (i >= s.size()) throw runtime_error("bad json object"); if (s[i] == '}') { ++i; break; } if (s[i] != ',') throw runtime_error("bad json object"); ++i;
        }
        return obj;
    }
};
JsonObj parseJson(const string& s) { JsonParser p(s); JsonObj obj = p.parseObject(); p.ws(); if (p.i != s.size()) throw runtime_error("trailing json"); return obj; }

string packFilePayload(const string& filePath, const vector<uint8_t>& dataBytes) {
    JsonObj obj;
    obj[FILE_MARKER] = JsonVal{JsonVal::Num, "1", {}};
    obj["name"] = JsonVal{JsonVal::Str, fs::path(filePath).filename().string(), {}};
    obj["size"] = JsonVal{JsonVal::Num, to_string(dataBytes.size()), {}};
    obj["data"] = JsonVal{JsonVal::Str, packPortableBytes(dataBytes), {}};
    return canonicalJson(obj);
}

bool unpackFilePayload(const string& text, string& name, vector<uint8_t>& data) {
    try {
        JsonObj obj = parseJson(text);
        auto it = obj.find(FILE_MARKER);
        if (it == obj.end() || it->second.s != "1") return false;
        name = obj.count("name") ? obj["name"].s : string("restored.bin");
        if (!obj.count("data")) return false;
        data = unpackPortableBytes(obj["data"].s);
        return true;
    } catch (...) {
        return false;
    }
}

struct Meta {
    int ver = 0, mode = 0; string alg; int suite = 0, kdfId = 0, macId = 0, flags = 0, chunkSize = 0; size_t origLen = 0, compLen = 0; vector<int> lens; string msgSeedDec, saltHex, nonceHex, ivHex; int count = 0, cmp = 0, powBits = 0; string verify, authTag, powNonce = "0", powHash;
};
JsonObj metaToJsonObj(const Meta& m, const set<string>& omit = {}) {
    JsonObj obj;
    auto addNum = [&](const string& k, const string& v) { if (omit.count(k)) return; JsonVal x; x.type = JsonVal::Num; x.s = v; obj[k] = x; };
    auto addStr = [&](const string& k, const string& v) { if (omit.count(k)) return; JsonVal x; x.type = JsonVal::Str; x.s = v; obj[k] = x; };
    auto addArr = [&](const string& k, const vector<int>& arr) { if (omit.count(k)) return; JsonVal x; x.type = JsonVal::ArrNum; for (int v : arr) x.arr.push_back(to_string(v)); obj[k] = x; };
    if (!m.alg.empty()) addStr("alg", m.alg);
    if (!m.authTag.empty()) addStr("authTag", m.authTag);
    if (m.chunkSize) addNum("chunkSize", to_string(m.chunkSize));
    if (m.cmp || (!omit.count("cmp") && (!m.alg.empty() || m.compLen || m.origLen))) addNum("cmp", to_string(m.cmp));
    addNum("compLen", to_string(m.compLen));
    if (m.count) addNum("count", to_string(m.count));
    if (m.flags) addNum("flags", to_string(m.flags));
    if (!m.ivHex.empty()) addStr("ivHex", lowerStr(m.ivHex));
    addNum("kdfId", to_string(m.kdfId)); addArr("lens", m.lens); addNum("macId", to_string(m.macId)); addNum("mode", to_string(m.mode)); if (!m.msgSeedDec.empty()) addStr("msgSeedDec", m.msgSeedDec); if (!m.nonceHex.empty()) addStr("nonceHex", lowerStr(m.nonceHex)); addNum("origLen", to_string(m.origLen)); addNum("powBits", to_string(m.powBits)); if (!m.powHash.empty()) addStr("powHash", lowerStr(m.powHash)); addNum("powNonce", m.powNonce.empty() ? string("0") : m.powNonce); if (!m.saltHex.empty()) addStr("saltHex", lowerStr(m.saltHex)); addNum("suite", to_string(m.suite)); if (!m.verify.empty()) addStr("verify", lowerStr(m.verify)); addNum("ver", to_string(m.ver));
    return obj;
}
Meta metaFromJsonObj(const JsonObj& obj) {
    auto getNum = [&](const string& k, const string& d = "0") -> string { auto it = obj.find(k); return it == obj.end() ? d : it->second.s; };
    auto getStr = [&](const string& k, const string& d = "") -> string { auto it = obj.find(k); return it == obj.end() ? d : it->second.s; };
    Meta m; m.ver = stoi(getNum("ver")); m.mode = stoi(getNum("mode")); m.alg = getStr("alg"); m.suite = stoi(getNum("suite")); m.kdfId = stoi(getNum("kdfId")); m.macId = stoi(getNum("macId")); m.flags = stoi(getNum("flags")); m.chunkSize = stoi(getNum("chunkSize")); m.origLen = static_cast<size_t>(stoull(getNum("origLen"))); m.compLen = static_cast<size_t>(stoull(getNum("compLen"))); auto itLens = obj.find("lens"); if (itLens != obj.end()) for (const string& v : itLens->second.arr) m.lens.push_back(stoi(v)); m.msgSeedDec = getStr("msgSeedDec"); m.saltHex = lowerStr(getStr("saltHex")); m.nonceHex = lowerStr(getStr("nonceHex")); m.ivHex = lowerStr(getStr("ivHex")); m.count = stoi(getNum("count", m.lens.empty() ? "0" : to_string(m.lens.size()))); m.cmp = stoi(getNum("cmp")); m.powBits = stoi(getNum("powBits")); m.verify = lowerStr(getStr("verify")); m.authTag = lowerStr(getStr("authTag")); m.powNonce = getNum("powNonce", "0"); m.powHash = lowerStr(getStr("powHash")); return m;
}
string buildMetaCore(const Meta& m, const set<string>& omit = {}) { return canonicalJson(metaToJsonObj(m, omit)); }
vector<uint8_t> sha256Bytes(const vector<uint8_t>& data) { vector<uint8_t> out(SHA256_DIGEST_LENGTH); SHA256(data.data(), data.size(), out.data()); return out; }
string sha256Hex(const vector<uint8_t>& data) { return bytesToHex(sha256Bytes(data)); }
int leadingZeroBits(const vector<uint8_t>& digest) {
    int n = 0; for (uint8_t b : digest) { if (b == 0) n += 8; else { int x = b, bits = 0; while (x > 0) { ++bits; x >>= 1; } return n + (8 - bits); } } return n;
}
vector<uint8_t> buildPowHeader(const Meta& meta, const string& bodyPacked) {
    set<string> omit = {"powNonce", "powHash"}; string core = buildMetaCore(meta, omit); vector<uint8_t> body(bodyPacked.begin(), bodyPacked.end()); string bodyHash = sha256Hex(body); string joined = core + "|" + bodyHash; return vector<uint8_t>(joined.begin(), joined.end());
}
vector<uint8_t> fixedBigEndian(const string& dec, size_t len) {
    cpp_int n = parseDec(dec); if (n < 0) throw runtime_error("negative fixed big-endian"); cpp_int lim = cpp_int(1); lim <<= (len * 8); if (n >= lim) throw runtime_error("integer too large for fixed bytes"); vector<uint8_t> out(len, 0); for (size_t i = 0; i < len; ++i) { size_t idx = len - 1 - i; out[idx] = static_cast<uint8_t>((n & 0xFF).convert_to<unsigned int>()); n >>= 8; } return out;
}
pair<string, string> solvePow(const Meta& meta, const string& bodyPacked, int bits = 0, const string& startNonce = "0") {
    if (bits <= 0) return {"0", ""}; vector<uint8_t> prefix = buildPowHeader(meta, bodyPacked); cpp_int nonce = parseDec(startNonce);
    while (true) {
        vector<uint8_t> nbytes = fixedBigEndian(decStr(nonce), 16); vector<uint8_t> data = prefix; data.insert(data.end(), nbytes.begin(), nbytes.end()); vector<uint8_t> digest = sha256Bytes(data);
        if (leadingZeroBits(digest) >= bits) return {decStr(nonce), bytesToHex(digest)}; nonce += 1;
    }
}
bool verifyEqual(const string& aIn, const string& bIn) { string a = aIn, b = bIn; unsigned int x = static_cast<unsigned int>(a.size() ^ b.size()); size_t m = max(a.size(), b.size()); for (size_t i = 0; i < m; ++i) { unsigned int ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0, cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0; x |= (ca ^ cb); } return x == 0; }
bool verifyPow(const Meta& meta, const string& bodyPacked) {
    if (meta.powBits <= 0) return true; vector<uint8_t> prefix = buildPowHeader(meta, bodyPacked); vector<uint8_t> nbytes = fixedBigEndian(meta.powNonce.empty() ? string("0") : meta.powNonce, 16); vector<uint8_t> data = prefix; data.insert(data.end(), nbytes.begin(), nbytes.end()); vector<uint8_t> digest = sha256Bytes(data); return verifyEqual(lowerStr(meta.powHash), bytesToHex(digest)) && leadingZeroBits(digest) >= meta.powBits;
}

uint32_t xrotl32(uint32_t x, int n) { x &= 0xFFFFFFFFu; return (x << n) | (x >> (32 - n)); }
void xquarter(uint32_t state[16], int a, int b, int c, int d) {
    state[a] = (state[a] + state[b]) & 0xFFFFFFFFu; state[d] ^= state[a]; state[d] = xrotl32(state[d], 16); state[c] = (state[c] + state[d]) & 0xFFFFFFFFu; state[b] ^= state[c]; state[b] = xrotl32(state[b], 12); state[a] = (state[a] + state[b]) & 0xFFFFFFFFu; state[d] ^= state[a]; state[d] = xrotl32(state[d], 8); state[c] = (state[c] + state[d]) & 0xFFFFFFFFu; state[b] ^= state[c]; state[b] = xrotl32(state[b], 7);
}
array<uint8_t, 32> hChaCha20(const array<uint8_t, 32>& key32, const array<uint8_t, 16>& nonce16) {
    uint32_t state[16]; const uint32_t cst[4] = {0x61707865u, 0x3320646Eu, 0x79622D32u, 0x6B206574u}; state[0] = cst[0]; state[1] = cst[1]; state[2] = cst[2]; state[3] = cst[3];
    for (int i = 0; i < 8; ++i) state[4 + i] = uint32_t(key32[i * 4]) | (uint32_t(key32[i * 4 + 1]) << 8) | (uint32_t(key32[i * 4 + 2]) << 16) | (uint32_t(key32[i * 4 + 3]) << 24);
    for (int i = 0; i < 4; ++i) state[12 + i] = uint32_t(nonce16[i * 4]) | (uint32_t(nonce16[i * 4 + 1]) << 8) | (uint32_t(nonce16[i * 4 + 2]) << 16) | (uint32_t(nonce16[i * 4 + 3]) << 24);
    uint32_t work[16]; memcpy(work, state, sizeof(work));
    for (int i = 0; i < 10; ++i) { xquarter(work, 0, 4, 8, 12); xquarter(work, 1, 5, 9, 13); xquarter(work, 2, 6, 10, 14); xquarter(work, 3, 7, 11, 15); xquarter(work, 0, 5, 10, 15); xquarter(work, 1, 6, 11, 12); xquarter(work, 2, 7, 8, 13); xquarter(work, 3, 4, 9, 14); }
    array<uint8_t, 32> out{}; uint32_t outWords[8] = {work[0], work[1], work[2], work[3], work[12], work[13], work[14], work[15]};
    for (int i = 0; i < 8; ++i) { out[i * 4] = uint8_t(outWords[i] & 0xFF); out[i * 4 + 1] = uint8_t((outWords[i] >> 8) & 0xFF); out[i * 4 + 2] = uint8_t((outWords[i] >> 16) & 0xFF); out[i * 4 + 3] = uint8_t((outWords[i] >> 24) & 0xFF); }
    return out;
}
vector<uint8_t> xChaCha20Poly1305Encrypt(const vector<uint8_t>& key32, const vector<uint8_t>& nonce24, const vector<uint8_t>& data, const vector<uint8_t>& aad = {}) {
    if (key32.size() != 32) throw runtime_error("key must be 32 bytes"); if (nonce24.size() != 24) throw runtime_error("nonce must be 24 bytes"); array<uint8_t, 32> keyArr{}; array<uint8_t, 16> nonce16{}; copy(key32.begin(), key32.end(), keyArr.begin()); copy(nonce24.begin(), nonce24.begin() + 16, nonce16.begin()); array<uint8_t, 32> subkey = hChaCha20(keyArr, nonce16); uint8_t nonce12[12] = {0}; memcpy(nonce12 + 4, nonce24.data() + 16, 8);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed"); int len = 0, outLen = 0; vector<uint8_t> out(data.size() + 16);
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_EncryptInit_ex failed"); }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_CTRL_AEAD_SET_IVLEN failed"); }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, subkey.data(), nonce12) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_EncryptInit_ex key/iv failed"); }
    if (!aad.empty() && EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_EncryptUpdate aad failed"); }
    if (!data.empty() && EVP_EncryptUpdate(ctx, out.data(), &len, data.data(), static_cast<int>(data.size())) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_EncryptUpdate data failed"); }
    outLen = len; if (EVP_EncryptFinal_ex(ctx, out.data() + outLen, &len) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_EncryptFinal_ex failed"); } outLen += len; unsigned char tag[16]; if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_CTRL_AEAD_GET_TAG failed"); } EVP_CIPHER_CTX_free(ctx); out.resize(outLen + 16); memcpy(out.data() + outLen, tag, 16); return out;
}
vector<uint8_t> xChaCha20Poly1305Decrypt(const vector<uint8_t>& key32, const vector<uint8_t>& nonce24, const vector<uint8_t>& data, const vector<uint8_t>& aad = {}) {
    if (key32.size() != 32) throw runtime_error("key must be 32 bytes"); if (nonce24.size() != 24) throw runtime_error("nonce must be 24 bytes"); if (data.size() < 16) throw runtime_error("ciphertext too short"); array<uint8_t, 32> keyArr{}; array<uint8_t, 16> nonce16{}; copy(key32.begin(), key32.end(), keyArr.begin()); copy(nonce24.begin(), nonce24.begin() + 16, nonce16.begin()); array<uint8_t, 32> subkey = hChaCha20(keyArr, nonce16); uint8_t nonce12[12] = {0}; memcpy(nonce12 + 4, nonce24.data() + 16, 8);
    size_t ctLen = data.size() - 16; const uint8_t* tag = data.data() + ctLen; EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed"); int len = 0, outLen = 0; vector<uint8_t> out(ctLen);
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_DecryptInit_ex failed"); }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_CTRL_AEAD_SET_IVLEN failed"); }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, subkey.data(), nonce12) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_DecryptInit_ex key/iv failed"); }
    if (!aad.empty() && EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_DecryptUpdate aad failed"); }
    if (ctLen > 0 && EVP_DecryptUpdate(ctx, out.data(), &len, data.data(), static_cast<int>(ctLen)) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_DecryptUpdate data failed"); }
    outLen = len; if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) { EVP_CIPHER_CTX_free(ctx); throw runtime_error("EVP_CTRL_AEAD_SET_TAG failed"); }
    int rc = EVP_DecryptFinal_ex(ctx, out.data() + outLen, &len); EVP_CIPHER_CTX_free(ctx); if (rc != 1) throw runtime_error("wrong key or damaged ciphertext"); outLen += len; out.resize(outLen); return out;
}

bool isExtendedKey(const string& k, int count = 8) {
    if (static_cast<int>(k.size()) != 64 + count) return false; int auxCount = 0; for (char ch : k) { if (gCharBase.find(ch) == string::npos) return false; if (gAuxBase.find(ch) != string::npos) ++auxCount; } return auxCount == count;
}
struct ExtKeyInfo { string bodyHex; vector<tuple<int, char, int>> sched; string schedText; string mixHex; vector<string> segments; };
ExtKeyInfo unpackExtendedKey(const string& k, int count = 8) {
    if (!isExtendedKey(k, count)) throw runtime_error("invalid extended key"); string body; vector<tuple<int, char, int>> sched; vector<string> segments; string cur;
    for (int pos = 0; pos < static_cast<int>(k.size()); ++pos) { char ch = k[pos]; size_t p = gAuxBase.find(ch); if (p != string::npos) { segments.push_back(cur); cur.clear(); sched.push_back({pos, ch, static_cast<int>(p)}); } else { cur.push_back(ch); body.push_back(ch); } }
    segments.push_back(cur); string bodyHex = lowerStr(body); if (!isHex64(bodyHex) || static_cast<int>(sched.size()) != count) throw runtime_error("invalid extended key structure"); string schedText = scheduleText(sched); string mixHex = lowerStr(computeBound(fold64("EXT|ROOT|" + bodyHex + "|" + schedText + "|" + to_string(count)) + bodyHex).first); return {bodyHex, sched, schedText, mixHex, segments};
}
pair<string, vector<int>> remixExtendedKey(const string& k, int count = 8) {
    ExtKeyInfo ext = unpackExtendedKey(k, count); vector<char> peppers; vector<int> vals; for (const auto& [_, ch, val] : ext.sched) { peppers.push_back(ch); vals.push_back(val); }
    vector<int> avail(ext.segments.size()); for (int i = 0; i < static_cast<int>(avail.size()); ++i) avail[i] = i; vector<int> order; uint64_t state = 0; for (int i = 0; i < static_cast<int>(vals.size()); ++i) state += uint64_t(i + 1) * uint64_t(vals[i] + 1); state += ext.bodyHex.size() + count;
    for (int i = 0; i < static_cast<int>(vals.size()); ++i) { int v = vals[i]; int pick = static_cast<int>((state + v + i + (v * (i + 3))) % avail.size()); order.push_back(avail[pick]); avail.erase(avail.begin() + pick); state = diffuseWord64(state ^ (uint64_t(v + 1) << ((i * 7) % 29))); }
    order.insert(order.end(), avail.begin(), avail.end()); vector<string> remixedSegments; for (int idx : order) remixedSegments.push_back(ext.segments[idx]); string out; for (size_t i = 0; i < peppers.size(); ++i) { out += remixedSegments[i]; out.push_back(peppers[i]); } out += remixedSegments.back(); return {out, order};
}
struct KeyPairInfo { string key1, key2, schedText, mixHex, remix; vector<int> order; };
KeyPairInfo computeKeyPair(const string& masterKey, int keyMode = 0, int count = 8) {
    int mode = keyMode == 0 ? 0 : 333;
    if (mode != 0 && isExtendedKey(masterKey, count)) {
        ExtKeyInfo ext = unpackExtendedKey(masterKey, count); auto remix = remixExtendedKey(masterKey, count); return {lowerStr(ext.bodyHex), lowerStr(generatePrimaryKey(masterKey + remix.first)), ext.schedText, ext.mixHex, remix.first, remix.second};
    }
    string base = lowerStr(trimStr(masterKey)); if (!isHex64(base)) base = lowerStr(generatePrimaryKey(masterKey)); return {base, lowerStr(generatePrimaryKey("PAIR|" + base)), "", "", "", {}};
}
string deriveInternalKey(const string& masterKey, int keyMode = 0, int count = 8, const string& label = "ROOT") {
    KeyPairInfo pair = computeKeyPair(masterKey, keyMode, count); string seed = fold64("KEY|" + label + "|" + pair.key1 + "|" + pair.key2 + "|" + pair.schedText + "|" + pair.mixHex + "|" + pair.remix + "|" + to_string(keyMode == 0 ? 0 : 333) + "|" + to_string(count)); return lowerStr(computeBound(seed + pair.key1 + pair.key2).first);
}
string deriveObfKey(const string& masterKey, int keyMode = 0, int count = 8) { return deriveInternalKey(masterKey, keyMode, count, "OBF"); }
pair<string, int> resolveKeyString(const string* k, bool allowAuto = false, int keyMode = 0, int count = 8) {
    if (k == nullptr) {
        if (!allowAuto) throw runtime_error("key/passphrase required");
        return {generateKey(keyMode, count), 0};
    }
    if (keyMode == 0) {
        string s = trimStr(*k);
        if (isHex64(s)) return {lowerStr(s), 0};
        return {lowerStr(generatePrimaryKey(*k)), 1};
    }
    string s = trimStr(*k);
    if (isExtendedKey(s, count)) return {s, 0};
    return {generateExtendedKey(*k, count), 1};
}

struct MessageKeys { string encRoot, authRoot, nonceRoot, verifyRoot, pubRoot; };
MessageKeys deriveMessageKeys(const string& masterKey, const string& saltHex, const string& nonceHex, const string& ivHex, int keyMode = 0, int count = 8) {
    string encBase = deriveInternalKey(masterKey, keyMode, count, "ENC"), authBase = deriveInternalKey(masterKey, keyMode, count, "AUTH"), nonceBase = deriveInternalKey(masterKey, keyMode, count, "NONCE"), verifyBase = deriveInternalKey(masterKey, keyMode, count, "VERIFY"), pubBase = deriveInternalKey(masterKey, keyMode, count, "PUBSEED");
    return {
        lowerStr(computeBound(fold64(encBase + saltHex + nonceHex + ivHex) + encBase).first),
        lowerStr(computeBound(fold64(authBase + ivHex + saltHex + nonceHex) + authBase).first),
        lowerStr(computeBound(fold64(nonceBase + nonceHex + ivHex + saltHex) + nonceBase).first),
        lowerStr(computeBound(fold64(verifyBase + saltHex + ivHex + nonceHex) + verifyBase).first),
        lowerStr(computeBound(fold64(pubBase + saltHex + nonceHex + ivHex) + pubBase).first)
    };
}
string deriveBlockKey(const string& encRoot, int chunkIndex, const string& saltHex, const string& nonceHex, const string& ivHex) {
    string idxHex = encodeHex(chunkIndex); if (idxHex.size() < 16) idxHex = string(16 - idxHex.size(), '0') + idxHex; if (idxHex.size() > 16) idxHex = idxHex.substr(idxHex.size() - 16); return lowerStr(computeBound(fold64(encRoot + saltHex + nonceHex + ivHex + idxHex) + encRoot + idxHex).first);
}
vector<uint8_t> hexToBytes(const string& sIn) { string s = lowerStr(sIn); if (s.size() % 2 != 0) throw runtime_error("hex string must have even length"); vector<uint8_t> out(s.size() / 2); for (size_t i = 0; i < out.size(); ++i) out[i] = static_cast<uint8_t>(hexPairValue(s, i * 2)); return out; }
vector<uint8_t> deriveChunkNonce(const string& nonceRoot, int chunkIndex, const string& saltHex, const string& nonceHex, const string& ivHex) { string idxHex = encodeHex(chunkIndex); if (idxHex.size() < 16) idxHex = string(16 - idxHex.size(), '0') + idxHex; if (idxHex.size() > 16) idxHex = idxHex.substr(idxHex.size() - 16); string a = lowerStr(computeBound(fold64(nonceRoot + saltHex + idxHex + nonceHex) + nonceRoot).first), b = lowerStr(computeBound(fold64(ivHex + idxHex + nonceRoot + saltHex) + nonceHex).first); return hexToBytes((a + b).substr(0, 48)); }
vector<uint8_t> buildChunkAad(const Meta& meta, int idx) { JsonObj obj; obj["alg"] = JsonVal{JsonVal::Str, meta.alg, {}}; obj["chunkSize"] = JsonVal{JsonVal::Num, to_string(meta.chunkSize), {}}; obj["compLen"] = JsonVal{JsonVal::Num, to_string(meta.compLen), {}}; obj["idx"] = JsonVal{JsonVal::Num, to_string(idx), {}}; obj["kdfId"] = JsonVal{JsonVal::Num, to_string(meta.kdfId), {}}; obj["mode"] = JsonVal{JsonVal::Num, to_string(meta.mode), {}}; obj["msgSeedDec"] = JsonVal{JsonVal::Str, meta.msgSeedDec, {}}; obj["origLen"] = JsonVal{JsonVal::Num, to_string(meta.origLen), {}}; obj["suite"] = JsonVal{JsonVal::Num, to_string(meta.suite), {}}; obj["ver"] = JsonVal{JsonVal::Num, to_string(meta.ver), {}}; string s = canonicalJson(obj); return vector<uint8_t>(s.begin(), s.end()); }
string computeVerifyToken(const string& verifyRoot, const Meta& meta) { set<string> omit = {"verify", "authTag", "powNonce", "powHash"}; return lowerStr(computeBound(fold64("VERIFY|" + verifyRoot + "|" + buildMetaCore(meta, omit)) + verifyRoot).first).substr(0, 32); }
string computeAuthTag(const string& authRoot, const Meta& meta, const string& bodyPacked, int detached = 0) { set<string> omit = {"authTag", "powNonce", "powHash"}; string chain = lowerStr(computeBound(fold64("AUTH|" + authRoot + "|" + buildMetaCore(meta, omit) + "|" + to_string(detached)) + authRoot).first); int stride = 256; int idx = 0; for (int off = 0; off < static_cast<int>(bodyPacked.size()); off += stride) { string block = bodyPacked.substr(off, stride); string idxHex = encodeHex(idx); if (idxHex.size() < 8) idxHex = string(8 - idxHex.size(), '0') + idxHex; chain = lowerStr(computeBound(fold64(chain + authRoot + idxHex + block) + authRoot).first); ++idx; } string idxHex = encodeHex(idx); if (idxHex.size() < 8) idxHex = string(8 - idxHex.size(), '0') + idxHex; return lowerStr(computeBound(fold64(chain + authRoot + idxHex) + authRoot).first); }
string encodeEnvelope(const Meta& meta, const string& bodyPacked) { string header = buildMetaCore(meta); vector<uint8_t> payload(4 + header.size() + bodyPacked.size()); uint32_t n = static_cast<uint32_t>(header.size()); payload[0] = uint8_t((n >> 24) & 0xFF); payload[1] = uint8_t((n >> 16) & 0xFF); payload[2] = uint8_t((n >> 8) & 0xFF); payload[3] = uint8_t(n & 0xFF); memcpy(payload.data() + 4, header.data(), header.size()); memcpy(payload.data() + 4 + header.size(), bodyPacked.data(), bodyPacked.size()); return packPortableBytes(payload); }
pair<Meta, string> decodeEnvelope(const string& token) { vector<uint8_t> payload = unpackPortableBytes(token); if (payload.size() < 4) throw runtime_error("invalid ciphertext envelope"); uint32_t n = (uint32_t(payload[0]) << 24) | (uint32_t(payload[1]) << 16) | (uint32_t(payload[2]) << 8) | uint32_t(payload[3]); if (payload.size() < 4 + n) throw runtime_error("invalid ciphertext envelope"); string header(reinterpret_cast<const char*>(payload.data() + 4), n); string body(reinterpret_cast<const char*>(payload.data() + 4 + n), payload.size() - 4 - n); return {metaFromJsonObj(parseJson(header)), body}; }
vector<uint8_t> zlibCompress(const vector<uint8_t>& raw, int level = 9) { uLongf outCap = compressBound(static_cast<uLong>(raw.size())); vector<uint8_t> out(outCap); int rc = compress2(out.data(), &outCap, raw.data(), static_cast<uLong>(raw.size()), level); if (rc != Z_OK) throw runtime_error("zlib compress failed"); out.resize(outCap); return out; }
vector<uint8_t> zlibDecompress(const vector<uint8_t>& raw, size_t expectLen) { uLongf outLen = static_cast<uLongf>(expectLen); vector<uint8_t> out(outLen); int rc = uncompress(out.data(), &outLen, raw.data(), static_cast<uLong>(raw.size())); if (rc != Z_OK) throw runtime_error("zlib decompress failed"); out.resize(outLen); return out; }

struct EncryptResult { bool detached = false; string cipher, key, meta, body; };
EncryptResult encryptData(const string& n, const string* k = nullptr, int keyMode = 0, int count = 8, bool detached = false, bool compress = true, int chunkSize = 2048, int powBits = 0, const string& powStart = "0", const string& saltHexIn = "", const string& nonceHexIn = "", const string& ivHexIn = "", bool showProgress = false, const string& progressLabel = "Encrypting") {
    auto started = chrono::steady_clock::now();
    int modeMarker = keyMode == 0 ? 0 : 333; auto resolved = resolveKeyString(k, true, keyMode == 0 ? 0 : 333, count); string hKey = resolved.first; int kdfId = resolved.second;
    string msgSeedDec = deriveWrapSeed(); SeedState ds = expandSeedState(msgSeedDec); string saltHex = saltHexIn.empty() ? ds.saltHex : lowerStr(saltHexIn), nonceHex = nonceHexIn.empty() ? ds.nonceHex : lowerStr(nonceHexIn), ivHex = ivHexIn.empty() ? ds.ivHex : lowerStr(ivHexIn);
    MessageKeys msgKeys = deriveMessageKeys(hKey, saltHex, nonceHex, ivHex, keyMode == 0 ? 0 : 333, count);
    vector<uint8_t> rawBytes = encodeUtf16Le(n); vector<uint8_t> compBytes = compress ? zlibCompress(rawBytes, 9) : rawBytes; auto parts = splitByteBlocks(compBytes, chunkSize);
    uint64_t total = static_cast<uint64_t>(parts.size()) + 5; if (showProgress) printProgBar(progressLabel, 1, total, started);
    vector<string> cipherParts; vector<int> lens;
    for (int idx = 0; idx < static_cast<int>(parts.size()); ++idx) {
        vector<uint8_t> chunkKey = hexToBytes(deriveBlockKey(msgKeys.encRoot, idx, saltHex, nonceHex, ivHex)); vector<uint8_t> chunkNonce = deriveChunkNonce(msgKeys.nonceRoot, idx, saltHex, nonceHex, ivHex);
        Meta metaAad; metaAad.ver = 2; metaAad.alg = "XCHACHA20-POLY1305"; metaAad.mode = modeMarker; metaAad.suite = keyMode == 0 ? 3 : 4; metaAad.kdfId = kdfId; metaAad.chunkSize = chunkSize; metaAad.origLen = rawBytes.size(); metaAad.compLen = compBytes.size(); metaAad.msgSeedDec = msgSeedDec;
        vector<uint8_t> cPart = xChaCha20Poly1305Encrypt(chunkKey, chunkNonce, parts[idx], buildChunkAad(metaAad, idx)); string packed = packPortableBytes(cPart); cipherParts.push_back(packed); lens.push_back(static_cast<int>(packed.size()));
        if (showProgress) printProgBar(progressLabel, static_cast<uint64_t>(idx) + 3, total, started);
    }
    string bodyPacked; for (const auto& p : cipherParts) bodyPacked += p;
    Meta meta; meta.ver = 2; meta.mode = modeMarker; meta.alg = "XCHACHA20-POLY1305"; meta.suite = keyMode == 0 ? 3 : 4; meta.kdfId = kdfId; meta.macId = 3; meta.flags = detached ? 7 : 3; meta.chunkSize = chunkSize; meta.origLen = rawBytes.size(); meta.compLen = compBytes.size(); meta.lens = lens; meta.msgSeedDec = msgSeedDec; meta.saltHex = saltHex; meta.nonceHex = nonceHex; meta.ivHex = ivHex; meta.count = count; meta.cmp = compress ? 1 : 0; meta.powBits = powBits; meta.verify = computeVerifyToken(msgKeys.verifyRoot, meta); meta.authTag = computeAuthTag(msgKeys.authRoot, meta, bodyPacked, detached ? 1 : 0);
    if (showProgress) printProgBar(progressLabel, total - 1, total, started);
    if (powBits > 0) { auto pow = solvePow(meta, bodyPacked, powBits, powStart); meta.powNonce = pow.first; meta.powHash = pow.second; } else { meta.powNonce = "0"; meta.powHash = ""; }
    EncryptResult out; out.detached = detached; out.key = hKey;
    if (detached) { string metaCore = buildMetaCore(meta); vector<uint8_t> metaBytes(metaCore.begin(), metaCore.end()); out.meta = packPortableBytes(metaBytes); out.body = bodyPacked; }
    else out.cipher = encodeEnvelope(meta, bodyPacked);
    if (showProgress) printProgBar(progressLabel, total, total, started);
    return out;
}

string decryptDataEx(const string& n, const string& k, int keyMode = -1, int count = 8, const string* metaPacked = nullptr, bool showProgress = false, const string& progressLabel = "Decrypting") {
    auto started = chrono::steady_clock::now();
    Meta metaObj; string bodyPacked;
    if (metaPacked) { vector<uint8_t> metaBytes = unpackPortableBytes(*metaPacked); string metaStr(metaBytes.begin(), metaBytes.end()); metaObj = metaFromJsonObj(parseJson(metaStr)); bodyPacked = n; }
    else { auto env = decodeEnvelope(n); metaObj = env.first; bodyPacked = env.second; }
    int modeValue = keyMode < 0 ? metaObj.mode : keyMode; int resolvedMode = modeValue == 0 ? 0 : 333; int effectiveCount = resolvedMode == 0 ? 8 : (metaObj.count ? metaObj.count : (count >= 1 ? count : 8)); auto resolved = resolveKeyString(&k, false, resolvedMode, effectiveCount); string hKey = resolved.first;
    MessageKeys msgKeys = deriveMessageKeys(hKey, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex, resolvedMode, effectiveCount);
    string expectVerify = computeVerifyToken(msgKeys.verifyRoot, metaObj); if (!verifyEqual(expectVerify, metaObj.verify)) throw runtime_error("wrong key or damaged ciphertext");
    string expectAuth = computeAuthTag(msgKeys.authRoot, metaObj, bodyPacked, (metaObj.flags & 4) ? 1 : 0); if (!verifyEqual(expectAuth, metaObj.authTag)) throw runtime_error("wrong key or damaged ciphertext");
    if (!verifyPow(metaObj, bodyPacked)) throw runtime_error("invalid proof-of-work");
    vector<string> parts; size_t pos = 0; for (int L : metaObj.lens) { if (pos + static_cast<size_t>(L) > bodyPacked.size()) throw runtime_error("wrong key or damaged ciphertext"); parts.push_back(bodyPacked.substr(pos, L)); pos += static_cast<size_t>(L); } if (pos != bodyPacked.size()) throw runtime_error("wrong key or damaged ciphertext");
    uint64_t total = static_cast<uint64_t>(parts.size()) + 5; if (showProgress) printProgBar(progressLabel, 2, total, started);
    vector<uint8_t> compOut; Meta metaAad; metaAad.ver = metaObj.ver; metaAad.alg = metaObj.alg; metaAad.mode = metaObj.mode; metaAad.suite = metaObj.suite; metaAad.kdfId = metaObj.kdfId; metaAad.chunkSize = metaObj.chunkSize; metaAad.origLen = metaObj.origLen; metaAad.compLen = metaObj.compLen; metaAad.msgSeedDec = metaObj.msgSeedDec;
    for (int idx = 0; idx < static_cast<int>(parts.size()); ++idx) {
        vector<uint8_t> chunkKey = hexToBytes(deriveBlockKey(msgKeys.encRoot, idx, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex)); vector<uint8_t> chunkNonce = deriveChunkNonce(msgKeys.nonceRoot, idx, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex); vector<uint8_t> packed = unpackPortableBytes(parts[idx]); vector<uint8_t> plain = xChaCha20Poly1305Decrypt(chunkKey, chunkNonce, packed, buildChunkAad(metaAad, idx)); compOut.insert(compOut.end(), plain.begin(), plain.end());
        if (showProgress) printProgBar(progressLabel, static_cast<uint64_t>(idx) + 3, total, started);
    }
    vector<uint8_t> rawBytes = compOut; if (metaObj.cmp == 1) rawBytes = zlibDecompress(compOut, metaObj.origLen); if (showProgress) printProgBar(progressLabel, total, total, started); return decodeSafeText(rawBytes);
}

string generatePublicKey(const string& k, int keyMode = 0, int count = 8) {
    auto resolved = resolveKeyString(&k, false, keyMode == 0 ? 0 : 333, count); string hKey = resolved.first; vector<uint8_t> seed = hexToBytes(deriveInternalKey(hKey, keyMode == 0 ? 0 : 333, count, "PUBSEED")); EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()); if (!pkey) throw runtime_error("failed to create Ed25519 private key"); size_t pubLen = 32; vector<uint8_t> pub(pubLen); if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pubLen) != 1) { EVP_PKEY_free(pkey); throw runtime_error("failed to derive Ed25519 public key"); } EVP_PKEY_free(pkey); pub.resize(pubLen); return packPortableBytes(pub);
}
struct SignResult { string signature, publicKey; };
SignResult signData(const string& data, const string& k, int keyMode = 0, int count = 8) {
    auto resolved = resolveKeyString(&k, false, keyMode == 0 ? 0 : 333, count); string hKey = resolved.first; vector<uint8_t> seed = hexToBytes(deriveInternalKey(hKey, keyMode == 0 ? 0 : 333, count, "PUBSEED")); EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()); if (!pkey) throw runtime_error("failed to create Ed25519 private key"); EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); if (!mdctx) { EVP_PKEY_free(pkey); throw runtime_error("EVP_MD_CTX_new failed"); } if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) != 1) { EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throw runtime_error("EVP_DigestSignInit failed"); } size_t sigLen = 0; if (EVP_DigestSign(mdctx, nullptr, &sigLen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) { EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throw runtime_error("EVP_DigestSign size failed"); } vector<uint8_t> sig(sigLen); if (EVP_DigestSign(mdctx, sig.data(), &sigLen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) { EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throw runtime_error("EVP_DigestSign failed"); } sig.resize(sigLen); size_t pubLen = 32; vector<uint8_t> pub(pubLen); if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pubLen) != 1) { EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throw runtime_error("EVP_PKEY_get_raw_public_key failed"); } EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); pub.resize(pubLen); return {packPortableBytes(sig), packPortableBytes(pub)};
}
bool verifySignature(const string& data, const string& signature, const string& publicKey) {
    vector<uint8_t> sig = unpackPortableBytes(signature), pub = unpackPortableBytes(publicKey); EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size()); if (!pkey) return false; EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); if (!mdctx) { EVP_PKEY_free(pkey); return false; } bool ok = false; if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) == 1) ok = EVP_DigestVerify(mdctx, sig.data(), sig.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1; EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); return ok;
}

vector<string> generateHashRange(const cpp_int& start, uint64_t hashes, int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096, bool bare = false, bool showProgress = false, const string& label = "HASH") {
    vector<string> out; out.reserve(static_cast<size_t>(hashes)); cpp_int cur = start; string curText = bare ? string() : decStr(start); auto started = chrono::steady_clock::now();
    for (uint64_t i = 0; i < hashes; ++i) { string hash = generateKey(cur, mode, count, directBits, laneBits, blockBytes); if (bare) out.push_back(hash); else { out.push_back(curText + " = " + hash); incDecString(curText); } cur += 1; if (showProgress) printProgBar(label, i + 1, hashes, started); }
    return out;
}
void writeHashRange(const string& path, const cpp_int& start, uint64_t hashes, int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096, bool bare = false, bool showProgress = true, const string& label = "HASH") {
    ofstream fp(path, ios::binary); if (!fp) throw runtime_error("failed to open output file: " + path); vector<char> ioBuf(1 << 20); fp.rdbuf()->pubsetbuf(ioBuf.data(), ioBuf.size()); cpp_int cur = start; string curText = bare ? string() : decStr(start); auto started = chrono::steady_clock::now();
    for (uint64_t i = 0; i < hashes; ++i) { string hash = generateKey(cur, mode, count, directBits, laneBits, blockBytes); if (bare) fp << hash << '\n'; else { fp << curText << " = " << hash << '\n'; incDecString(curText); } if (!fp) throw runtime_error("failed while writing output file: " + path); cur += 1; if (showProgress) printProgBar(label, i + 1, hashes, started); }
}
void benchRange(const cpp_int& start, uint64_t hashes, int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096) {
    cpp_int cur = start; auto started = chrono::steady_clock::now(); string last; for (uint64_t i = 0; i < hashes; ++i) { last = generateKey(cur, mode, count, directBits, laneBits, blockBytes); cur += 1; } auto elapsed = chrono::duration_cast<chrono::duration<long double>>(chrono::steady_clock::now() - started).count(); long double rate = elapsed > 0 ? (static_cast<long double>(hashes) / elapsed) : 0.0L; cout << "hashes=" << hashes << '\n' << "elapsed=" << fixed << setprecision(6) << elapsed << '\n' << "hashesPerSec=" << fixed << setprecision(6) << rate << '\n' << "last=" << last << '\n';
}
vector<cpp_int> makeBenchInputs(uint64_t hashes, bool randomInputs = true, int inputBits = 256, const cpp_int& start = 0) {
    vector<cpp_int> out; out.reserve(static_cast<size_t>(hashes));
    if (inputBits < 1) inputBits = 1;
    cpp_int mask = (cpp_int(1) << inputBits) - 1;
    if (randomInputs) {
        size_t nbytes = static_cast<size_t>((inputBits + 7) / 8);
        for (uint64_t i = 0; i < hashes; ++i) out.push_back(bytesToInt(secureRandomBytes(nbytes)) & mask);
    } else {
        cpp_int cur = start;
        for (uint64_t i = 0; i < hashes; ++i) { out.push_back(cur); cur += 1; }
    }
    return out;
}

shepAudit::HashBytes32 hashHexToBytes32(const string& hexIn) {
    string hex = lowerStr(trimStr(hexIn));
    if (!isHex64(hex)) throw runtime_error("expected a 64-hex digest");
    shepAudit::HashBytes32 out{};
    auto nib = [](char ch) -> uint8_t {
        if (ch >= '0' && ch <= '9') return uint8_t(ch - '0');
        if (ch >= 'a' && ch <= 'f') return uint8_t(ch - 'a' + 10);
        throw runtime_error("bad hex digit");
    };
    for (size_t i = 0; i < 32; ++i) out[i] = uint8_t((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    return out;
}

shepAudit::HashBytes32 shepAuditBytesForInput(const cpp_int& x, int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096) {
    string out = generateKey(x, mode, count, directBits, laneBits, blockBytes);
    if (isHex64(out)) return hashHexToBytes32(out);
    string auditHex = lowerStr(deriveInternalKey(out, mode == 0 ? 0 : 333, count, "AUDIT"));
    return hashHexToBytes32(auditHex);
}

struct BenchSummary {
    uint64_t hashes = 0;
    long double elapsed = 0.0L;
    long double hashesPerSec = 0.0L;
    string last;
    bool randomInputs = true;
    int inputBits = 128;
    bool compare = false;
    bool deepAudit = false;
    size_t topCount = 128;
    string auditDir;
    long double shepMeanFlipRate = 0.0L;
    long double sha256MeanFlipRate = 0.0L;
    vector<shepAudit::CompareRow> compareRows;
    string compareTable;
    bool hasDualAudit = false;
    shepAudit::BothResult dualAudit;
};

BenchSummary benchRun(uint64_t hashes, bool randomInputs = true, int inputBits = 128, const cpp_int& start = 0, int mode = 0, int count = 8, int directBits = 256, int laneBits = 336, int blockBytes = 4096, bool compare = false, bool showProgress = true, bool deepAudit = false, size_t topCount = 128, const string& auditDir = "") {
    vector<cpp_int> inputs = makeBenchInputs(hashes, randomInputs, inputBits, start);
    BenchSummary sum; sum.hashes = hashes; sum.randomInputs = randomInputs; sum.inputBits = inputBits; sum.compare = compare; sum.deepAudit = deepAudit; sum.topCount = topCount; sum.auditDir = auditDir;
    auto started = chrono::steady_clock::now();
    string last;
    for (uint64_t i = 0; i < hashes; ++i) {
        last = generateKey(inputs[static_cast<size_t>(i)], mode, count, directBits, laneBits, blockBytes);
        if (showProgress) printProgBar("Benchmarking", i + 1, hashes, started);
    }
    auto elapsed = chrono::duration_cast<chrono::duration<long double>>(chrono::steady_clock::now() - started).count();
    sum.elapsed = elapsed;
    sum.hashesPerSec = elapsed > 0 ? (static_cast<long double>(hashes) / elapsed) : 0.0L;
    sum.last = last;
    if (!compare) return sum;
    shepAudit::Options opts;
    opts.samples = inputs;
    opts.maxBits = inputBits;
    opts.deep = deepAudit;
    opts.outDir = auditDir;
    opts.showProgress = showProgress;
    opts.topCount = topCount;
    auto fn = [=](const cpp_int& x) -> shepAudit::HashBytes32 {
        return shepAuditBytesForInput(x, mode, count, directBits, laneBits, blockBytes);
    };
    auto both = shepAudit::runDualAudit(fn, opts, true);
    sum.shepMeanFlipRate = both.shep32.summary.overallMeanFlipRate;
    sum.sha256MeanFlipRate = both.sha256.summary.overallMeanFlipRate;
    sum.compareRows = shepAudit::sideBySide(both, 10, true);
    sum.compareTable = shepAudit::formatCompareTable(sum.compareRows);
    sum.hasDualAudit = true;
    sum.dualAudit = both;
    return sum;
}

void writeBenchReport(const string& path, const BenchSummary& sum) {
    ofstream fp(path, ios::binary);
    if (!fp) throw runtime_error("failed to open output file: " + path);
    fp << "hashes\t" << sum.hashes << "\n";
    fp << "elapsed\t" << fixed << setprecision(6) << sum.elapsed << "\n";
    fp << "hashesPerSec\t" << fixed << setprecision(6) << sum.hashesPerSec << "\n";
    fp << "last\t" << sum.last << "\n";
    fp << "randomInputs\t" << (sum.randomInputs ? "true" : "false") << "\n";
    fp << "inputBits\t" << sum.inputBits << "\n";
    fp << "compare\t" << (sum.compare ? "true" : "false") << "\n";
    if (sum.compare) {
        fp << "deepAudit\t" << (sum.deepAudit ? "true" : "false") << "\n";
        fp << "topCount\t" << sum.topCount << "\n";
        fp << "auditDir\t" << sum.auditDir << "\n";
        fp << "shepMeanFlipRate\t" << fixed << setprecision(10) << sum.shepMeanFlipRate << "\n";
        fp << "sha256MeanFlipRate\t" << fixed << setprecision(10) << sum.sha256MeanFlipRate << "\n\n";
        fp << "metric\tkind\tworstCase\tmidCase\tshepDelta\tshep\toptimal\tsha256\tshaDelta\tbetter\tadvantage\n";
        for (const auto& r : sum.compareRows) fp << r.metric << '\t' << r.kind << '\t' << r.worstCase << '\t' << r.midCase << '\t' << r.shepDelta << '\t' << r.shep32 << '\t' << r.optimal << '\t' << r.sha256 << '\t' << r.shaDelta << '\t' << r.better << '\t' << r.advantage << '\n';
    }
}

void printHelp(const char* exe) {
    cout << "Usage:\n"
         << "  " << exe << " [hash input] [options]\n"
         << "  " << exe << " --encrypt TEXT --key KEY [options]\n"
         << "  " << exe << " --encrypt-file PATH --key KEY [options]\n"
         << "  " << exe << " --decrypt TOKEN --key KEY [options]\n"
         << "  " << exe << " --decrypt-file PATH --key KEY [options]\n"
         << "  " << exe << " --body BODY --meta META --key KEY [options]\n\n"
         << "Hash inputs:\n"
         << "  --text TEXT         Generate a SHEP64 or SHEP333 key from UTF-8 text\n"
         << "  --value INT         Generate a SHEP64 or SHEP333 key from a decimal integer\n"
         << "  --file PATH         Generate a SHEP64 or SHEP333 key from file contents\n"
         << "  --start INT         Starting integer for range generation\n"
         << "  --hashes N          Number of keys to generate from --start\n"
         << "  --out PATH          Write range or cipher output to file\n\n"
         << "Encryption / decryption:\n"
         << "  --encrypt TEXT      Encrypt UTF-8 text into a .sh32 token\n"
         << "  --encrypt-file PATH Encrypt a file payload\n"
         << "  --decrypt TOKEN     Decrypt a .sh32 token\n"
         << "  --decrypt-file PATH Decrypt a token file\n"
         << "  --stdin             Read payload from stdin\n"
         << "  --delim NAME        Read NAME:BEGIN ... NAME:END from stdin\n"
         << "  --detached          Use detached meta/body format\n"
         << "  --meta META         Detached meta token or file path\n"
         << "  --body BODY         Detached body token or file path\n"
         << "  --key KEY           Passphrase, primary key, or extended key\n"
         << "  --keyfile PATH      Read a SHEP key from a .pkey file\n"
         << "  --write-key PATH    Save the resulting SHEP key to a .pkey file\n"
         << "  --quiet-key         Do not print the key token\n"
         << "  --no-compress       Disable zlib compression before encryption\n"
         << "  --chunk-size N      Chunk units of 2048 bytes (default 1)\n"
         << "  --chunk-bytes N     Exact chunk size in bytes\n"
         << "  --pow-bits N        Proof-of-work difficulty bits\n"
         << "  --pow-start N       Starting nonce for proof-of-work\n"
         << "  --as-text           Do not auto-restore wrapped files on decrypt\n"
         << "  --no-limit          Override the default encrypt-file size cap\n"
         << "  --no-progress       Disable progress bars\n\n"
         << "Other features:\n"
         << "  --pubkey            Derive an Ed25519 public key from a SHEP key\n"
         << "  --sign TEXT         Sign UTF-8 text\n"
         << "  --verify TEXT       Verify UTF-8 text using --signature and --public-key\n"
         << "  --pair              Print the internal encryption key pair\n\n"
         << "General options:\n"
         << "  --mode N            0 = SHEP64 primary, 1 = SHEP333 extended\n"
         << "  --direct-bits N     Direct-route threshold bits (default 256)\n"
         << "  --lane-bits N       Reserved compatibility option (default 336)\n"
         << "  --block-bytes N     Reserved compatibility option (default 4096 or 65536 for files)\n"
         << "  --bare              Output only hashes in range mode\n"
         << "  --bench N           Benchmark N hashes; random inputs by default\n"
         << "  --input-bits N      Benchmark input width in 2..256 (default 128)\n"
         << "  --compare           Add diffusion audit against SHA-256\n"
         << "  --deep-audit        Include pair-dependence analysis in compare mode\n"
         << "  --top-count N       Top-cell count for compare mode (default 128)\n"
         << "  --audit-dir PATH    Write detailed audit TSV files to PATH\n"
         << "  --help              Show this help\n";
}

string readTextPath(const string& path) {
    ifstream fp(path, ios::binary);
    if (!fp) throw runtime_error("failed to open file: " + path);
    stringstream ss;
    ss << fp.rdbuf();
    return ss.str();
}

void writeTextPath(const string& path, const string& data) {
    ofstream fp(path, ios::binary);
    if (!fp) throw runtime_error("failed to open output file: " + path);
    fp << data;
    if (!fp) throw runtime_error("failed to write output file: " + path);
}

void writeBinPath(const string& path, const vector<uint8_t>& data) {
    ofstream fp(path, ios::binary);
    if (!fp) throw runtime_error("failed to open output file: " + path);
    if (!data.empty()) fp.write(reinterpret_cast<const char*>(data.data()), static_cast<streamsize>(data.size()));
    if (!fp) throw runtime_error("failed to write output file: " + path);
}

string formatKeyFile(const string& token) {
    return KEY_HEADER + trimStr(token) + KEY_FOOTER;
}

void writeKeyFilePath(const string& path, const string& token) {
    writeTextPath(path, formatKeyFile(token));
}

string parseKeyFileText(const string& text) {
    string t = text;
    string kh = trimStr(KEY_HEADER), kf = trimStr(KEY_FOOTER);
    size_t a = t.find(kh), b = a == string::npos ? string::npos : t.find(kf, a + kh.size());
    if (a != string::npos && b != string::npos && b > a) {
        string mid = t.substr(a + kh.size());
        size_t nl = mid.find('\n');
        if (nl != string::npos) mid = mid.substr(nl + 1);
        size_t end = mid.find(kf);
        if (end != string::npos) mid = trimStr(mid.substr(0, end));
        if (!mid.empty()) return mid;
    }
    stringstream ss(t);
    string line;
    while (getline(ss, line)) {
        line = trimStr(line);
        if (!line.empty()) return line;
    }
    throw runtime_error("invalid key file format");
}

string loadKeyFile(const string& path) {
    return parseKeyFileText(readTextPath(path));
}

string ensureExtPath(const string& raw, const string& ext, const string& fallbackName) {
    fs::path p = trimStr(raw).empty() ? fs::path(fallbackName) : fs::path(trimStr(raw));
    if (!p.has_extension()) p.replace_extension(ext);
    return p.string();
}

string defaultEncOutPath(const string& inPath) {
    fs::path p(inPath);
    return p.replace_extension(".sh32").string();
}

string defaultKeyOutPath(const string& cipherPath) {
    fs::path p(cipherPath);
    return p.replace_extension(".pkey").string();
}

bool endsWithNoCase(const string& s, const string& suffix) {
    if (suffix.size() > s.size()) return false;
    string a = lowerStr(s.substr(s.size() - suffix.size()));
    string b = lowerStr(suffix);
    return a == b;
}

string keyBasePath(const string& rawPath) {
    string s = trimStr(rawPath);
    if (s.empty()) return "output";
    if (endsWithNoCase(s, ".sh32.body")) return s.substr(0, s.size() - 10);
    if (endsWithNoCase(s, ".sh32.meta")) return s.substr(0, s.size() - 10);
    if (endsWithNoCase(s, ".sh32")) return s.substr(0, s.size() - 5);
    fs::path p(s);
    if (p.has_extension()) return p.replace_extension("").string();
    return s;
}

string defaultDetachedBodyPath(const string& basePath) {
    return keyBasePath(basePath) + ".sh32.body";
}

string defaultDetachedMetaPath(const string& basePath) {
    return keyBasePath(basePath) + ".sh32.meta";
}

string defaultDetachedKeyPath(const string& basePath) {
    return keyBasePath(basePath) + ".pkey";
}

string askLine(const string& prompt);
int askInt(const string& prompt, int defVal);

int askCountForMode(int mode, int defVal = FIXED_COUNT) {
    (void)mode;
    (void)defVal;
    return FIXED_COUNT;
}

int askDecryptCountOverride(int mode) {
    (void)mode;
    return FIXED_COUNT;
}

string askLine(const string& prompt) {
    cout << prompt;
    string s;
    getline(cin, s);
    return s;
}

int askInt(const string& prompt, int defVal) {
    string s = askLine(prompt);
    if (trimStr(s).empty()) return defVal;
    return stoi(trimStr(s));
}

bool askYesNo(const string& prompt, bool defVal = false) {
    string s = lowerStr(trimStr(askLine(prompt)));
    if (s.empty()) return defVal;
    return s == "y" || s == "yes" || s == "1" || s == "true";
}

string maybeLoadTokenText(const string& value) {
    string s = trimStr(value);
    try {
        if (!s.empty()) {
            ifstream fp(s, ios::binary);
            if (fp) {
                stringstream ss;
                ss << fp.rdbuf();
                return trimStr(ss.str());
            }
        }
    } catch (...) {}
    return s;
}

string askKeySource(bool require, bool allowAuto = true) {
    cout << "Key source: 1) direct key  2) passphrase  3) key file";
    if (allowAuto) cout << "  4) auto";
    cout << "\n> ";
    string choice; getline(cin, choice); choice = trimStr(choice);
    if (choice == "1") return trimStr(askLine("Key: "));
    if (choice == "2") return askLine("Passphrase: ");
    if (choice == "3") return loadKeyFile(trimStr(askLine("Key file path: ")));
    if (allowAuto && (choice.empty() || choice == "4")) return "";
    if (require) {
        cerr << "A key source is required.\n";
        return askKeySource(true, allowAuto);
    }
    return "";
}

int askChunkUnits(int defVal = 1) {
    string s = trimStr(askLine("Chunk size units x2048 [default 1]: "));
    if (s.empty()) return resolveChunkBytes(defVal, -1);
    return resolveChunkBytes(stoi(s), -1);
}

int interactiveMenu() {
    while (true) {
        cout << "SHEP Interactive Menu\n"
             << "1) Hash\n"
             << "2) Encrypt\n"
             << "3) Decrypt\n"
             << "4) Generate Key\n"
             << "5) Public Key\n"
             << "6) Sign\n"
             << "7) Verify\n"
             << "8) Range\n"
             << "9) Benchmark\n"
             << "0) Exit\n> ";
        string choice; getline(cin, choice); choice = trimStr(choice);
        try {
            if (choice == "0" || choice == "10" || choice == "q" || choice == "quit" || choice == "exit") return 0;
            if (choice == "1") {
                int mode = askInt("Mode 0=SHEP64, 1=SHEP333 [default 0]: ", 0);
                int count = FIXED_COUNT;
                string kind = trimStr(askLine("Input type: 1) text  2) file [default 1]: "));
                if (kind == "2") cout << generateKeyFile(trimStr(askLine("File path: ")), mode, count) << '\n';
                else cout << generateKey(askLine("Text: "), mode, count) << '\n';
                continue;
            }
            if (choice == "2") {
                int mode = askInt("Mode 0=SHEP64, 1=SHEP333 [default 0]: ", 0);
                int count = FIXED_COUNT;
                bool advanced = askYesNo("Advanced options? [y/N]: ", false);
                bool detached = false, noCompress = false;
                int chunkBytes = CHUNK_UNIT, powBits = 0; string powStart = "0";
                if (advanced) {
                    detached = askYesNo("Detached output? [y/N]: ", false);
                    noCompress = askYesNo("Disable compression? [y/N]: ", false);
                    chunkBytes = askChunkUnits(1);
                    powBits = askInt("Proof-of-work bits [default 0]: ", 0);
                    powStart = trimStr(askLine("Proof-of-work start nonce [default 0]: "));
                    if (powStart.empty()) powStart = "0";
                }
                string kind = trimStr(askLine("Input type: 1) text  2) file : "));
                string keyIn = askKeySource(false, true);
                const string* keyPtr = keyIn.empty() ? nullptr : &keyIn;
                if (kind == "2") {
                    string fp = trimStr(askLine("File path: "));
                    uint64_t size = fs::file_size(fp); bool noLimit = false;
                    if (size > DEFAULT_MAX_BYTES) noLimit = askYesNo("File exceeds the default limit. Override limit? [y/N]: ", false);
                    validateFileCap(fp, noLimit);
                    string payload = packFilePayload(fp, readFileBytes(fp));
                    EncryptResult res = encryptData(payload, keyPtr, mode == 0 ? 0 : 333, count, detached, !noCompress, chunkBytes, powBits, powStart, "", "", "", true, "Encrypting");
                    if (detached) {
                        string base = trimStr(askLine("Base output path [default input stem]: "));
                        if (base.empty()) base = fs::path(fp).replace_extension("").string();
                        string bodyPath = defaultDetachedBodyPath(base), metaPath = defaultDetachedMetaPath(base);
                        writeTextPath(bodyPath, res.body); writeTextPath(metaPath, res.meta);
                        string defaultKeyPath = defaultDetachedKeyPath(base);
                        string keyPath = trimStr(askLine("Key file path [default " + defaultKeyPath + "]: "));
                        if (keyPath.empty()) keyPath = defaultKeyPath;
                        writeKeyFilePath(keyPath, res.key);
                        cout << bodyPath << '\n' << metaPath << '\n' << keyPath << '\n';
                    } else {
                        string defaultOutPath = defaultEncOutPath(fp);
                        string outPath = trimStr(askLine("Output path [default " + defaultOutPath + "]: "));
                        if (outPath.empty()) outPath = defaultOutPath; else outPath = ensureExtPath(outPath, ".sh32", defaultOutPath);
                        writeTextPath(outPath, res.cipher);
                        string defaultKeyPath = defaultKeyOutPath(outPath);
                        string keyPath = trimStr(askLine("Key file path [default " + defaultKeyPath + "]: "));
                        if (keyPath.empty()) keyPath = defaultKeyPath;
                        writeKeyFilePath(keyPath, res.key);
                        cout << outPath << '\n' << keyPath << '\n';
                    }
                } else {
                    string text = askLine("Plaintext: ");
                    EncryptResult res = encryptData(text, keyPtr, mode == 0 ? 0 : 333, count, detached, !noCompress, chunkBytes, powBits, powStart, "", "", "", true, "Encrypting");
                    bool save = askYesNo("Save ciphertext to .sh32 file? [y/N]: ", false);
                    if (detached) {
                        if (save) {
                            string base = trimStr(askLine("Base output path [default cipher]: "));
                            if (base.empty()) base = "cipher";
                            string bodyPath = defaultDetachedBodyPath(base), metaPath = defaultDetachedMetaPath(base);
                            writeTextPath(bodyPath, res.body); writeTextPath(metaPath, res.meta);
                            string defaultKeyPath = defaultDetachedKeyPath(base);
                            string keyPath = trimStr(askLine("Key file path [default " + defaultKeyPath + "]: "));
                            if (keyPath.empty()) keyPath = defaultKeyPath;
                            writeKeyFilePath(keyPath, res.key);
                            cout << bodyPath << '\n' << metaPath << '\n' << keyPath << '\n';
                        } else {
                            cout << "meta=" << res.meta << '\n' << "body=" << res.body << '\n' << res.key << '\n';
                        }
                    } else {
                        if (save) {
                            string defaultOutPath = "cipher.sh32";
                            string outPath = trimStr(askLine("Output path [default " + defaultOutPath + "]: "));
                            if (outPath.empty()) outPath = defaultOutPath; else outPath = ensureExtPath(outPath, ".sh32", defaultOutPath);
                            writeTextPath(outPath, res.cipher);
                            string defaultKeyPath = defaultKeyOutPath(outPath);
                            string keyPath = trimStr(askLine("Key file path [default " + defaultKeyPath + "]: "));
                            if (keyPath.empty()) keyPath = defaultKeyPath;
                            writeKeyFilePath(keyPath, res.key);
                            cout << outPath << '\n' << keyPath << '\n';
                        } else {
                            cout << res.cipher << '\n' << res.key << '\n';
                        }
                    }
                }
                continue;
            }
            if (choice == "3") {
                string modeText = trimStr(askLine("Mode 0=SHEP64, 1=SHEP333, blank=auto: "));
                int mode = modeText.empty() ? -1 : (stoi(modeText) == 0 ? 0 : 333);
                int count = askDecryptCountOverride(mode);
                bool advanced = askYesNo("Advanced options? [y/N]: ", false);
                bool asText = false, detachedIn = false;
                if (advanced) {
                    asText = askYesNo("Treat output as text only? [y/N]: ", false);
                    detachedIn = askYesNo("Detached input? [y/N]: ", false);
                }
                string kind = trimStr(askLine("Input type: 1) text  2) file : "));
                string keyIn = askKeySource(true, false);
                string pt;
                if (detachedIn) {
                    if (kind == "2") {
                        string bodyPath = trimStr(askLine("Body file path: "));
                        string metaPath = trimStr(askLine("Meta file path: "));
                        string body = trimStr(readTextPath(bodyPath)), meta = trimStr(readTextPath(metaPath));
                        pt = decryptDataEx(body, keyIn, mode, count, &meta, true, "Decrypting");
                    } else {
                        string body = maybeLoadTokenText(askLine("Body token: "));
                        string meta = maybeLoadTokenText(askLine("Meta token: "));
                        pt = decryptDataEx(body, keyIn, mode, count, &meta, true, "Decrypting");
                    }
                } else {
                    if (kind == "2") {
                        string fp = trimStr(askLine("Token file path: "));
                        pt = decryptDataEx(trimStr(readTextPath(fp)), keyIn, mode, count, nullptr, true, "Decrypting");
                    } else {
                        string token = trimStr(askLine("Ciphertext token: "));
                        pt = decryptDataEx(token, keyIn, mode, count, nullptr, true, "Decrypting");
                    }
                }
                string restoredName; vector<uint8_t> restoredData;
                if (!asText && unpackFilePayload(pt, restoredName, restoredData)) {
                    string outPath = trimStr(askLine("Restore output path [default restored name]: "));
                    if (outPath.empty()) outPath = restoredName;
                    writeBinPath(outPath, restoredData);
                    cout << outPath << '\n';
                } else {
                    bool save = askYesNo("Save plaintext to file? [y/N]: ", false);
                    if (save) {
                        string outPath = trimStr(askLine("Output path [default plain.txt]: "));
                        if (outPath.empty()) outPath = "plain.txt";
                        writeTextPath(outPath, pt);
                        cout << outPath << '\n';
                    } else {
                        cout << pt << '\n';
                    }
                }
                continue;
            }
            if (choice == "4") {
                int mode = askInt("Mode 0=SHEP64, 1=SHEP333 [default 0]: ", 0);
                int count = FIXED_COUNT;
                string kind = trimStr(askLine("Generate source: 1) random  2) text  3) file [default 1]: "));
                string out;
                if (kind == "2") out = generateKey(askLine("Text: "), mode, count);
                else if (kind == "3") out = generateKeyFile(trimStr(askLine("File path: ")), mode, count);
                else out = generateKey(mode, count);
                cout << out << '\n';
                string save = trimStr(askLine("Save to key file (blank to skip): "));
                if (!save.empty()) { writeKeyFilePath(save, out); cout << save << '\n'; }
                continue;
            }
            if (choice == "5") { int mode = askInt("Mode 0=SHEP64, 1=SHEP333 [default 0]: ", 0); int count = FIXED_COUNT; string keyIn = askKeySource(true, false); cout << generatePublicKey(keyIn, mode == 0 ? 0 : 333, count) << '\n'; continue; }
            if (choice == "6") { int mode = askInt("Mode 0=SHEP64, 1=SHEP333 [default 0]: ", 0); int count = FIXED_COUNT; string keyIn = askKeySource(true, false); string text = askLine("Text to sign: "); SignResult sig = signData(text, keyIn, mode == 0 ? 0 : 333, count); cout << "signature=" << sig.signature << '\n' << "publicKey=" << sig.publicKey << '\n'; continue; }
            if (choice == "7") { string text = askLine("Text to verify: "); string sig = maybeLoadTokenText(askLine("Signature token or file path: ")); string pub = maybeLoadTokenText(askLine("Public key token or file path: ")); cout << (verifySignature(text, sig, pub) ? "true" : "false") << '\n'; continue; }
            if (choice == "8") { int mode = askInt("Mode 0=SHEP64, 1=SHEP333 [default 0]: ", 0); int count = FIXED_COUNT; cpp_int start = parseDec(trimStr(askLine("Start integer: "))); uint64_t hashes = parseU64(trimStr(askLine("How many hashes: ")), "hashes"); bool bare = askYesNo("Bare hashes only? [y/N]: ", false); auto lines = generateHashRange(start, hashes, mode, count, 256, 336, 4096, bare, false, "HASH"); for (const auto& line : lines) cout << line << '\n'; continue; }
            if (choice == "9") {
                int mode = askInt("Mode 0=SHEP64, 1=SHEP333 [default 0]: ", 0);
                int count = FIXED_COUNT;
                string benchType = trimStr(askLine("Benchmark type: 1) speed  2) speed + diffusion report [default 1]: "));
                if (benchType.empty()) benchType = "1";
                bool compare = benchType == "2";
                bool randomInputs = !askYesNo("Use sequential inputs instead of random? [y/N]: ", false);
                string hashesText = trimStr(askLine("How many inputs / hashes [default 1000]: "));
                uint64_t benchHashes = parseU64(hashesText.empty() ? string("1000") : hashesText, "hashes");
                string bitsText = trimStr(askLine("Input bits 2..256 [default 128]: "));
                int benchBits = bitsText.empty() ? 128 : stoi(bitsText);
                if (benchBits < 2 || benchBits > 256) throw runtime_error("input bits must be in 2..256");
                cpp_int benchStart = 0;
                if (!randomInputs) {
                    string startText = trimStr(askLine("Start integer [default 0]: "));
                    if (!startText.empty()) benchStart = parseDec(startText);
                }
                bool deepAudit = false;
                size_t topCount = 128;
                string auditDir;
                if (compare) {
                    deepAudit = askYesNo("Deep pair analysis? [y/N]: ", false);
                    string topText = trimStr(askLine("Top cell count [default 128]: "));
                    if (!topText.empty()) topCount = static_cast<size_t>(parseU64(topText, "top cell count"));
                    auditDir = trimStr(askLine("Detailed audit output directory [blank to skip]: "));
                }
                bool save = askYesNo("Save benchmark report to file? [y/N]: ", false);
                string savePath;
                if (save) {
                    savePath = trimStr(askLine("Output path [default bench.tsv]: "));
                    if (savePath.empty()) savePath = "bench.tsv";
                }
                bool showBenchProgress = !askYesNo("Hide progress? [y/N]: ", false);
                BenchSummary sum = benchRun(benchHashes, randomInputs, benchBits, benchStart, mode, count, 256, 336, 4096, compare, showBenchProgress, deepAudit, topCount, auditDir);
                if (!savePath.empty()) {
                    writeBenchReport(savePath, sum);
                    cout << savePath << "\n";
                } else {
                    cout << "hashes=" << sum.hashes << "\n"
                         << "elapsed=" << fixed << setprecision(6) << sum.elapsed << "\n"
                         << "hashesPerSec=" << fixed << setprecision(6) << sum.hashesPerSec << "\n"
                         << "last=" << sum.last << "\n"
                         << "randomInputs=" << (sum.randomInputs ? "true" : "false") << "\n"
                         << "inputBits=" << sum.inputBits << "\n";
                    if (sum.compare) {
                        cout << "shepMeanFlipRate=" << fixed << setprecision(10) << sum.shepMeanFlipRate << "\n"
                             << "sha256MeanFlipRate=" << fixed << setprecision(10) << sum.sha256MeanFlipRate << "\n"
                             << sum.compareTable;
                    }
                }
                continue;
            }
            cerr << "error: unknown selection\n";
        } catch (const exception& e) { cerr << "error: " << e.what() << '\n'; }
    }
}

int main(int argc, char* argv[]) {
    try {
        if (argc == 1) return interactiveMenu();
        bool hasText = false, hasValue = false, hasFile = false, hasStart = false, hasHashes = false, bare = false, showProgress = true, hasBench = false, doEncrypt = false, doEncryptFile = false, doDecrypt = false, doDecryptFile = false, doDetached = false, noCompress = false, doPubKey = false, doSign = false, doVerify = false, hasMeta = false, hasBody = false, hasKey = false, hasKeyFile = false, hasSignature = false, hasPublicKey = false, hasWriteKey = false, doPair = false, asText = false, quietKey = false, noLimit = false, useStdin = false, benchCompare = false, benchRandomInputs = true;
        string textValue, filePath, delim; cpp_int valueInt = 0, startValue = 0; uint64_t hashes = 0, benchCount = 0; string outPath; string encryptText, encryptFilePath, decryptToken, decryptFilePath, metaToken, bodyToken, keyText, keyFilePath, writeKeyPath, signText, verifyText, signatureText, publicKeyText; int mode = 0, count = FIXED_COUNT, directBits = 256, laneBits = 336, blockBytes = 4096, chunkSizeUnits = 1, chunkBytesArg = -1, powBits = 0, inputBits = 128; string powStart = "0"; bool benchDeepAudit = false; size_t benchTopCount = 128; string benchAuditDir;
        for (int i = 1; i < argc; ++i) {
            string arg = argv[i]; auto need = [&](const string& name) -> string { if (i + 1 >= argc || string(argv[i + 1]).rfind("--", 0) == 0) throw runtime_error("missing value for " + name); return string(argv[++i]); };
            if (arg == "--text") { hasText = true; textValue = need(arg); }
            else if (arg == "--value") { hasValue = true; valueInt = parseDec(need(arg)); }
            else if (arg == "--file") { hasFile = true; filePath = need(arg); }
            else if (arg == "--stdin") useStdin = true;
            else if (arg == "--delim") delim = need(arg);
            else if (arg == "--start") { hasStart = true; startValue = parseDec(need(arg)); }
            else if (arg == "--hashes") { hasHashes = true; hashes = parseU64(need(arg), "--hashes"); }
            else if (arg == "--out") outPath = need(arg);
            else if (arg == "--mode") mode = stoi(need(arg));
            else if (arg == "--direct-bits") directBits = stoi(need(arg));
            else if (arg == "--lane-bits") laneBits = stoi(need(arg));
            else if (arg == "--block-bytes") blockBytes = stoi(need(arg));
            else if (arg == "--chunk-size") chunkSizeUnits = stoi(need(arg));
            else if (arg == "--chunk-bytes") chunkBytesArg = stoi(need(arg));
            else if (arg == "--pow-bits") powBits = stoi(need(arg));
            else if (arg == "--pow-start") powStart = need(arg);
            else if (arg == "--encrypt") { doEncrypt = true; encryptText = need(arg); }
            else if (arg == "--encrypt-file") { doEncryptFile = true; encryptFilePath = need(arg); }
            else if (arg == "--decrypt") { doDecrypt = true; decryptToken = need(arg); }
            else if (arg == "--decrypt-file") { doDecryptFile = true; decryptFilePath = need(arg); }
            else if (arg == "--detached") doDetached = true;
            else if (arg == "--meta") { hasMeta = true; metaToken = need(arg); }
            else if (arg == "--body") { hasBody = true; bodyToken = need(arg); }
            else if (arg == "--key") { hasKey = true; keyText = need(arg); }
            else if (arg == "--keyfile") { hasKeyFile = true; keyFilePath = need(arg); }
            else if (arg == "--write-key") { hasWriteKey = true; writeKeyPath = need(arg); }
            else if (arg == "--no-compress") noCompress = true;
            else if (arg == "--pubkey") doPubKey = true;
            else if (arg == "--sign") { doSign = true; signText = need(arg); }
            else if (arg == "--verify") { doVerify = true; verifyText = need(arg); }
            else if (arg == "--signature") { hasSignature = true; signatureText = need(arg); }
            else if (arg == "--public-key") { hasPublicKey = true; publicKeyText = need(arg); }
            else if (arg == "--pair") doPair = true;
            else if (arg == "--as-text") asText = true;
            else if (arg == "--quiet-key") quietKey = true;
            else if (arg == "--no-limit") noLimit = true;
            else if (arg == "--bare") bare = true;
            else if (arg == "--no-progress") showProgress = false;
            else if (arg == "--bench") { hasBench = true; benchCount = parseU64(need(arg), "--bench"); }
            else if (arg == "--input-bits") inputBits = stoi(need(arg));
            else if (arg == "--compare") benchCompare = true;
            else if (arg == "--deep-audit") benchDeepAudit = true;
            else if (arg == "--top-count") benchTopCount = static_cast<size_t>(parseU64(need(arg), "--top-count"));
            else if (arg == "--audit-dir") benchAuditDir = need(arg);
            else if (arg == "--sequential") benchRandomInputs = false;
            else if (arg == "--random-inputs") benchRandomInputs = true;
            else if (arg == "--help" || arg == "-h") { printHelp(argv[0]); return 0; }
            else throw runtime_error("unknown argument: " + arg);
        }

        if (hasKey && hasKeyFile) throw runtime_error("provide only one of --key or --keyfile");
        if (hasKeyFile) keyText = loadKeyFile(keyFilePath), hasKey = true;
        if (mode != 0 && mode != 1 && mode != 333) throw runtime_error("--mode must be 0 or 1");
        if (directBits < 1) throw runtime_error("--direct-bits must be >= 1");
        if (powBits < 0) throw runtime_error("--pow-bits must be >= 0");
        if (inputBits < 2 || inputBits > 256) throw runtime_error("--input-bits must be in 2..256");
        int chunkBytes = resolveChunkBytes(chunkSizeUnits, chunkBytesArg);

        if (doPair) {
            int pairMode = mode == 0 ? 0 : 333; string master;
            if (hasFile) master = generateKeyFile(filePath, pairMode == 0 ? 0 : 1, count, directBits, laneBits, blockBytes);
            else if (hasValue) master = generateKey(valueInt, pairMode == 0 ? 0 : 1, count, directBits, laneBits, blockBytes);
            else if (hasText) master = generateKey(textValue, pairMode == 0 ? 0 : 1, count, directBits, laneBits, blockBytes);
            else throw runtime_error("--pair requires --text, --value, or --file");
            auto pair = computeKeyPair(master, pairMode, count);
            cout << "key1=" << pair.key1 << '\n' << "key2=" << pair.key2 << '\n' << "schedText=" << pair.schedText << '\n' << "mixHex=" << pair.mixHex << '\n' << "remix=" << pair.remix << '\n';
            return 0;
        }
        if (doPubKey) {
            if (!hasKey) throw runtime_error("--key or --keyfile is required for --pubkey");
            cout << generatePublicKey(keyText, mode == 0 ? 0 : 333, count) << '\n';
            return 0;
        }
        if (doSign) {
            if (!hasKey) throw runtime_error("--key or --keyfile is required for --sign");
            string payload = useStdin ? readStdinPayload(delim) : signText;
            SignResult sig = signData(payload, keyText, mode == 0 ? 0 : 333, count);
            cout << "signature=" << sig.signature << '\n' << "publicKey=" << sig.publicKey << '\n';
            return 0;
        }
        if (doVerify) {
            if (!hasSignature || !hasPublicKey) throw runtime_error("--signature and --public-key are required for --verify");
            string payload = useStdin ? readStdinPayload(delim) : verifyText;
            cout << (verifySignature(payload, maybeLoadTokenText(signatureText), maybeLoadTokenText(publicKeyText)) ? "true" : "false") << '\n';
            return 0;
        }

        if (doEncryptFile || (doEncrypt && hasFile)) {
            string src = doEncryptFile ? encryptFilePath : filePath; validateFileCap(src, noLimit); const string* keyPtr = hasKey ? &keyText : nullptr; string payload = packFilePayload(src, readFileBytes(src)); EncryptResult res = encryptData(payload, keyPtr, mode == 0 ? 0 : 333, count, doDetached, !noCompress, chunkBytes, powBits, powStart, "", "", "", showProgress, "Encrypting");
            if (doDetached) {
                string base = outPath.empty() ? fs::path(src).replace_extension("").string() : outPath; string bodyPath = defaultDetachedBodyPath(base), metaPath = defaultDetachedMetaPath(base); writeTextPath(bodyPath, res.body); writeTextPath(metaPath, res.meta); string keyPath = hasWriteKey ? writeKeyPath : defaultDetachedKeyPath(base); writeKeyFilePath(keyPath, res.key); cout << bodyPath << '\n' << metaPath << '\n' << keyPath << '\n'; if (!quietKey) cout << res.key << '\n';
            } else {
                string cipherPath = outPath.empty() ? defaultEncOutPath(src) : ensureExtPath(outPath, ".sh32", "cipher.sh32"); writeTextPath(cipherPath, res.cipher); string keyPath = hasWriteKey ? writeKeyPath : defaultKeyOutPath(cipherPath); writeKeyFilePath(keyPath, res.key); cout << cipherPath << '\n' << keyPath << '\n'; if (!quietKey) cout << res.key << '\n';
            }
            return 0;
        }
        if (doEncrypt) {
            const string* keyPtr = hasKey ? &keyText : nullptr; string payload = useStdin ? readStdinPayload(delim) : encryptText; EncryptResult res = encryptData(payload, keyPtr, mode == 0 ? 0 : 333, count, doDetached, !noCompress, chunkBytes, powBits, powStart, "", "", "", showProgress, "Encrypting");
            if (doDetached) {
                if (!outPath.empty()) { string bodyPath = defaultDetachedBodyPath(outPath), metaPath = defaultDetachedMetaPath(outPath); writeTextPath(bodyPath, res.body); writeTextPath(metaPath, res.meta); string keyPath = hasWriteKey ? writeKeyPath : defaultDetachedKeyPath(outPath); writeKeyFilePath(keyPath, res.key); cout << bodyPath << '\n' << metaPath << '\n' << keyPath << '\n'; }
                else { cout << "meta=" << res.meta << '\n' << "body=" << res.body << '\n'; if (hasWriteKey) { writeKeyFilePath(writeKeyPath, res.key); cout << writeKeyPath << '\n'; } else if (!quietKey) cout << res.key << '\n'; }
            } else {
                if (!outPath.empty()) { string cipherPath = ensureExtPath(outPath, ".sh32", "cipher.sh32"); writeTextPath(cipherPath, res.cipher); string keyPath = hasWriteKey ? writeKeyPath : defaultKeyOutPath(cipherPath); writeKeyFilePath(keyPath, res.key); cout << cipherPath << '\n' << keyPath << '\n'; }
                else { cout << res.cipher << '\n'; if (hasWriteKey) { writeKeyFilePath(writeKeyPath, res.key); cout << writeKeyPath << '\n'; } else if (!quietKey) cout << res.key << '\n'; }
            }
            return 0;
        }
        if (doDecryptFile || (doDecrypt && hasFile) || hasBody || hasMeta || doDecrypt) {
            if (!hasKey) throw runtime_error("--key or --keyfile is required for decryption");
            string pt; int decMode = mode == 333 ? 333 : (mode == 1 ? 333 : (mode == 0 ? 0 : -1));
            if (hasBody || hasMeta) {
                if (!hasBody || !hasMeta) throw runtime_error("--body and --meta must both be provided for detached decryption");
                string metaMaybe = maybeLoadTokenText(metaToken); pt = decryptDataEx(maybeLoadTokenText(bodyToken), keyText, decMode, count, &metaMaybe, showProgress, "Decrypting");
            } else if (doDecryptFile || (doDecrypt && hasFile)) {
                string src = doDecryptFile ? decryptFilePath : filePath; pt = decryptDataEx(trimStr(readTextPath(src)), keyText, decMode, count, nullptr, showProgress, "Decrypting");
            } else {
                string token = useStdin ? readStdinPayload(delim) : decryptToken; pt = decryptDataEx(token, keyText, decMode, count, nullptr, showProgress, "Decrypting");
            }
            string restoredName; vector<uint8_t> restoredData;
            if (!asText && unpackFilePayload(pt, restoredName, restoredData)) { string target = outPath.empty() ? restoredName : outPath; writeBinPath(target, restoredData); cout << target << '\n'; }
            else if (!outPath.empty()) { writeTextPath(outPath, pt); cout << outPath << '\n'; }
            else { cout << pt << '\n'; }
            return 0;
        }
        if (hasBench) {
            bool randomInputs = benchRandomInputs && !hasStart;
            BenchSummary sum = benchRun(benchCount, randomInputs, inputBits, hasStart ? startValue : cpp_int(0), mode, count, directBits, laneBits, blockBytes, benchCompare, showProgress, benchDeepAudit, benchTopCount, benchAuditDir);
            if (!outPath.empty()) {
                writeBenchReport(outPath, sum);
                cout << outPath << "\n";
            } else {
                cout << "hashes=" << sum.hashes << "\n"
                     << "elapsed=" << fixed << setprecision(6) << sum.elapsed << "\n"
                     << "hashesPerSec=" << fixed << setprecision(6) << sum.hashesPerSec << "\n"
                     << "last=" << sum.last << "\n"
                     << "randomInputs=" << (sum.randomInputs ? "true" : "false") << "\n"
                     << "inputBits=" << sum.inputBits << "\n";
                if (sum.compare) cout << "shepMeanFlipRate=" << fixed << setprecision(10) << sum.shepMeanFlipRate << "\n"
                                      << "sha256MeanFlipRate=" << fixed << setprecision(10) << sum.sha256MeanFlipRate << "\n"
                                      << sum.compareTable;
            }
            return 0;
        }
        if (hasStart || hasHashes || !outPath.empty()) {
            if (!hasStart) throw runtime_error("--start is required for range mode");
            if (!hasHashes) throw runtime_error("--hashes is required for range mode");
            if (outPath.empty()) { auto lines = generateHashRange(startValue, hashes, mode, count, directBits, laneBits, blockBytes, bare, false, "HASH"); for (const auto& line : lines) cout << line << '\n'; }
            else writeHashRange(outPath, startValue, hashes, mode, count, directBits, laneBits, blockBytes, bare, showProgress, "HASH");
            return 0;
        }
        if (hasFile) { cout << generateKeyFile(filePath, mode, count, directBits, laneBits, 65536) << '\n'; return 0; }
        if (hasText) { cout << generateKey(textValue, mode, count, directBits, laneBits, blockBytes) << '\n'; return 0; }
        if (hasValue) { cout << generateKey(valueInt, mode, count, directBits, laneBits, blockBytes) << '\n'; return 0; }
        cout << generateKey(mode, count, directBits, laneBits, blockBytes) << '\n';
        return 0;
    } catch (const exception& e) {
        cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
