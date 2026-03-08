#include <boost/multiprecision/cpp_int.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <limits>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;
using boost::multiprecision::cpp_int;

const string gCharBase = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`\"',_!#";
const string gAuxBase = "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

string deriveCharset(size_t c) { return gCharBase.substr(0, c); }
string deriveAuxCharset() { return gAuxBase; }

cpp_int parseDec(const string& s) {
    if (s.empty()) throw runtime_error("empty decimal string");
    cpp_int out = 0;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
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
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
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
            ++i;
            ++j;
            if (i >= n) {
                mt[0] = mt[n - 1];
                i = 1;
            }
            if (j >= keyLength) j = 0;
        }
        for (int k = n - 1; k > 0; --k) {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1566083941u)) - i;
            mt[i] &= 0xFFFFFFFFu;
            ++i;
            if (i >= n) {
                mt[0] = mt[n - 1];
                i = 1;
            }
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
        while (t > 0) {
            ++k;
            t >>= 1;
        }
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

vector<string> computeRadixDigits(cpp_int val, int b) {
    if (val == 0) return {"0"};
    if (val < 0) throw runtime_error("negative not supported in radix digits");
    vector<string> out;
    while (val > 0) {
        cpp_int rem = val % b;
        val /= b;
        out.push_back(rem.convert_to<string>());
    }
    reverse(out.begin(), out.end());
    return out;
}

cpp_int decodeRadixStream(const vector<string>& parts, int b) {
    cpp_int res = 0;
    for (const auto& p : parts) res = res * b + parseDec(p);
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
        if (curBn * it->second <= target) {
            curBn *= it->second;
            n += it->first;
        }
    }
    cpp_int geomSum = n > 0 ? (powInt(b, n) - b) / (b - 1) : 0;
    cpp_int r = d - geomSum;
    return n == 0 ? "" : encodeRadix(r, b, n, c);
}

cpp_int decodeShift(const string& c, int b) {
    string s = c;
    size_t l = s.size();
    if (b == 10) return parseDec(s) + (l > 1 ? (powInt(10, l) - 10) / 9 : 0);
    if (b == 16) return parseStdBase(s, 16) + (l > 1 ? (powInt(16, l) - 16) / 15 : 0);
    static unordered_map<int, unordered_map<char, int>> cache;
    if (!cache.count(b)) {
        string chars = deriveCharset(b);
        for (int i = 0; i < b; ++i) cache[b][chars[i]] = i;
    }
    auto& charMap = cache[b];
    cpp_int v = 0;
    for (char ch : s) v = v * b + charMap[ch];
    cpp_int geomSum = (b > 1 && l > 1) ? (powInt(b, l) - b) / (b - 1) : cpp_int(0);
    return v + geomSum;
}

string generateKeystream(const cpp_int& s, int n) {
    DeterministicRng32 r(s);
    string out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) out.push_back(char('0' + r.randint(0, 8).convert_to<int>()));
    return out;
}

string diffuseSequence(const string& s, const cpp_int& c) {
    string keystream = generateKeystream(c, static_cast<int>(s.size()));
    string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) out.push_back(char((((s[i] + keystream[i] - 96) % 10) + 48)));
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
    string out = "1";
    int stop = width - rem;
    for (int idx = 0; idx < stop; idx += f) {
        string chunk = bitstream.substr(idx, f);
        reverse(chunk.begin(), chunk.end());
        out += chunk;
    }
    if (rem) out += bitstream.substr(stop);
    return parseStdBase(out, 2);
}

cpp_int diffuseBits(const cpp_int& s, const string& k) {
    string bitstream = dropPrefixBit(s);
    string keyText;
    for (char ch : k) if (ch != '0') keyText.push_back(ch);
    if (keyText.empty()) return parseStdBase("1" + string(bitstream.rbegin(), bitstream.rend()), 2);
    vector<int> stride;
    for (char ch : keyText) stride.push_back((ch - '0') + 1);
    string out = "1";
    int pos = 0;
    int turn = 0;
    while (pos < static_cast<int>(bitstream.size())) {
        int step = stride[turn % static_cast<int>(stride.size())];
        string chunk = bitstream.substr(pos, step);
        reverse(chunk.begin(), chunk.end());
        out += chunk;
        pos += step;
        ++turn;
    }
    return parseStdBase(out, 2);
}

cpp_int distributeRadix(const cpp_int& n, const cpp_int& k, int b = 8, int y = 1) {
    int seedBase = 1 << 16;
    vector<string> stateDigits = computeRadixDigits(n, b);
    vector<string> schedule;
    for (const auto& x : computeRadixDigits(k, seedBase)) if (x.size() >= 2 && x.size() <= 10) schedule.push_back(x);
    if (schedule.empty()) schedule.push_back(decStr((k % (seedBase - 2)) + 2));
    size_t limit = (stateDigits.size() + 2) * 40;
    size_t need = y == 1 ? stateDigits.size() + 1 : stateDigits.size();
    size_t loops = 0;
    while (schedule.size() < need) {
        cpp_int nextSeed = parseDec(schedule.back()) + seedBase;
        for (const auto& x : computeRadixDigits(nextSeed, seedBase)) if (x.size() >= 2 && x.size() <= 10) schedule.push_back(x);
        ++loops;
        if (loops > limit) break;
    }
    while (schedule.size() < need) schedule.push_back(schedule.back());
    if (y == 1) {
        int guard = (1 - (stoi(schedule[0]) % b)) % b;
        vector<string> mixed;
        mixed.reserve(stateDigits.size() + 1);
        mixed.push_back(to_string(guard));
        mixed.insert(mixed.end(), stateDigits.begin(), stateDigits.end());
        vector<string> out;
        out.reserve(mixed.size());
        for (size_t i = 0; i < mixed.size(); ++i) out.push_back(to_string((stoi(mixed[i]) + stoi(schedule[i])) % b));
        return decodeRadixStream(out, b);
    }
    vector<string> out;
    out.reserve(stateDigits.size());
    for (size_t i = 0; i < stateDigits.size(); ++i) out.push_back(to_string((stoi(stateDigits[i]) - stoi(schedule[i]) + b * 1000) % b));
    if (out.size() <= 1) return 0;
    return decodeRadixStream(vector<string>(out.begin() + 1, out.end()), b);
}

int decodeDigit(char ch) { return ch - '0'; }

const array<array<cpp_int, 10>, 10>& computePiMatrix() {
    static array<array<cpp_int, 10>, 10> box{};
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 10; ++i) {
            for (int j = 0; j < 10; ++j) {
                double z = acos(-1.0) / ((i + 1.0) * (j + 1.0));
                double fracVal = z - floor(z);
                char buf[128];
                auto res = std::to_chars(buf, buf + sizeof(buf), fracVal, std::chars_format::general);
                string s;
                if (res.ec == std::errc()) s.assign(buf, res.ptr);
                else {
                    ostringstream ss;
                    ss << std::setprecision(std::numeric_limits<double>::max_digits10) << std::defaultfloat << fracVal;
                    s = ss.str();
                }
                auto dot = s.find('.');
                string frac = dot == string::npos ? "0" : s.substr(dot + 1);
                auto epos = frac.find_first_of("eE");
                if (epos != string::npos) frac = frac.substr(0, epos);
                if (frac.empty()) frac = "0";
                box[i][j] = parseDec(frac);
            }
        }
        init = true;
    }
    return box;
}

string prefixProduct(const string& n, const string& m, size_t p) { return decStr(parseDec(n) * parseDec(m)).substr(0, p); }

string biasTransform(const string& n, size_t p) {
    int seed = decodeDigit(n[0]);
    string out;
    out.reserve(p);
    for (size_t i = 0; i < p; ++i) out.push_back(char((((decodeDigit(n[i % n.size()]) + seed) % 10) + 48)));
    return out;
}

string prefixSquare(const string& n, const string& m, size_t p) {
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
    int routeB = (seed - tap) % 6;
    if (routeB < 0) routeB += 6;

    state = routeA == 0 ? prefixProduct(state, key, width) : routeA == 1 ? biasTransform(state, width) : routeA == 2 ? prefixSquare(state, key, width) : routeA == 3 ? digitProduct(state, key, width) : routeA == 4 ? integratePi(state, width) : executeCascade(state, key, width);
    state = routeB == 0 ? prefixSquare(state, key, width) : routeB == 1 ? digitProduct(state, key, width) : routeB == 2 ? executeCascade(state, key, width) : routeB == 3 ? biasTransform(state, width) : routeB == 4 ? prefixProduct(state, key, width) : executeCascade(state, key, width);

    char hi = '2';
    char lo = '3';
    for (char ch : state) if (isdigit(static_cast<unsigned char>(ch)) && ch != '0') { hi = ch; break; }
    for (size_t i = 1; i < state.size(); ++i) if (isdigit(static_cast<unsigned char>(state[i])) && state[i] != '0') { lo = state[i]; break; }

    state = decStr(distributeBits(distributeBits(parseDec(state) + parseDec(permuteSuffix(state)))));
    state = decStr(decodeShift(permutePrefix(state), 10));
    cpp_int mask = parseDec(string() + hi + lo + string(width >= 2 ? width - 2 : 0, '0'));
    string out = decStr(parseDec(state) + mask + parseDec(key));
    return out.size() <= width ? out : out.substr(out.size() - width);
}

int deriveBaseFactor(const string& hex64) {
    string x = hex64;
    transform(x.begin(), x.end(), x.begin(), [](unsigned char c){ return char(tolower(c)); });
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

cpp_int encodeTextBlock(const string& t) {
    vector<uint8_t> b;
    b.reserve(1 + t.size() * 2);
    b.push_back(0x01);
    for (unsigned char ch : t) {
        b.push_back(ch);
        b.push_back(0x00);
    }
    cpp_int out = 0;
    for (uint8_t x : b) {
        out <<= 8;
        out += x;
    }
    return out;
}

string fold64(const string& h) {
    auto rot = [](uint64_t x, int r) -> uint64_t {
        return (x << r) | (x >> (64 - r));
    };
    auto mix = [](uint64_t x) -> uint64_t {
        x ^= x >> 31;
        x *= 0x7FB5D329728EA185ULL;
        x ^= x >> 27;
        x *= 0x81DADEF4BC2DD44DULL;
        x ^= x >> 33;
        x *= 0xD6E8FEB86659FD93ULL;
        x ^= x >> 29;
        return x;
    };
    auto word = [](const vector<uint8_t>& b, size_t i) -> uint64_t {
        return uint64_t(b[i]) | (uint64_t(b[i + 1]) << 8) | (uint64_t(b[i + 2]) << 16) | (uint64_t(b[i + 3]) << 24) |
               (uint64_t(b[i + 4]) << 32) | (uint64_t(b[i + 5]) << 40) | (uint64_t(b[i + 6]) << 48) | (uint64_t(b[i + 7]) << 56);
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

        uint64_t w0 = mix(x0 ^ a ^ x8 ^ 0x9E3779B97F4A7C15ULL);
        uint64_t w1 = mix(x1 ^ b ^ x9 ^ 0xC2B2AE3D27D4EB4FULL);
        uint64_t w2 = mix(x2 ^ c ^ x10 ^ 0x165667B19E3779F9ULL);
        uint64_t w3 = mix(x3 ^ d ^ x11 ^ 0x85EBCA77C2B2AE63ULL);
        uint64_t w4 = mix(x4 ^ e ^ x12 ^ 0x27D4EB2F165667C5ULL);
        uint64_t w5 = mix(x5 ^ f ^ x13 ^ 0x94D049BB133111EBULL);
        uint64_t w6 = mix(x6 ^ g ^ x14 ^ 0xD6E8FEB86659FD93ULL);
        uint64_t w7 = mix(x7 ^ j ^ x15 ^ 0xA5A3564E27F8862DULL);

        for (int round = 0; round < 12; ++round) {
            uint64_t t0 = mix(a + w0 + rot(e ^ w4, 17) + rot(f ^ w5, 9));
            uint64_t t1 = mix(b + w1 + rot(f ^ w5, 29) + rot(g ^ w6, 21));
            uint64_t t2 = mix(c + w2 + rot(g ^ w6, 41) + rot(j ^ w7, 33));
            uint64_t t3 = mix(d + w3 + rot(j ^ w7, 11) + rot(a ^ w0, 45));
            uint64_t t4 = mix(e + w4 + rot(a ^ w0, 23) + rot(b ^ w1, 37));
            uint64_t t5 = mix(f + w5 + rot(b ^ w1, 31) + rot(c ^ w2, 49));
            uint64_t t6 = mix(g + w6 + rot(c ^ w2, 13) + rot(d ^ w3, 57));
            uint64_t t7 = mix(j + w7 + rot(d ^ w3, 27) + rot(e ^ w4, 39));

            a = mix(t0 ^ rot(t3, 7) ^ w1);
            b = mix(t1 ^ rot(t4, 11) ^ w2);
            c = mix(t2 ^ rot(t5, 19) ^ w3);
            d = mix(t3 ^ rot(t6, 23) ^ w4);
            e = mix(t4 ^ rot(t7, 31) ^ w5);
            f = mix(t5 ^ rot(t0, 37) ^ w6);
            g = mix(t6 ^ rot(t1, 43) ^ w7);
            j = mix(t7 ^ rot(t2, 53) ^ w0);

            w0 = mix(w0 ^ a ^ rot(w4, 9));
            w1 = mix(w1 ^ b ^ rot(w5, 13));
            w2 = mix(w2 ^ c ^ rot(w6, 17));
            w3 = mix(w3 ^ d ^ rot(w7, 21));
            w4 = mix(w4 ^ e ^ rot(w0, 25));
            w5 = mix(w5 ^ f ^ rot(w1, 29));
            w6 = mix(w6 ^ g ^ rot(w2, 33));
            w7 = mix(w7 ^ j ^ rot(w3, 37));

            uint64_t oa = a, ob = b, oc = c, od = d, oe = e, of = f, og = g, oj = j;
            a = oc; c = oe; e = og; g = oa;
            b = of; d = ob; f = oj; j = od;
        }

        a = mix(a ^ x0 ^ x9 ^ w2);
        b = mix(b ^ x1 ^ x10 ^ w3);
        c = mix(c ^ x2 ^ x11 ^ w4);
        d = mix(d ^ x3 ^ x12 ^ w5);
        e = mix(e ^ x4 ^ x13 ^ w6);
        f = mix(f ^ x5 ^ x14 ^ w7);
        g = mix(g ^ x6 ^ x15 ^ w0);
        j = mix(j ^ x7 ^ x8 ^ w1);
    }

    uint64_t p = mix(a ^ c ^ e ^ g ^ 0x243F6A8885A308D3ULL);
    uint64_t q = mix(b ^ d ^ f ^ j ^ 0x13198A2E03707344ULL);
    uint64_t r = mix(a ^ b ^ e ^ f ^ 0xA4093822299F31D0ULL);
    uint64_t t = mix(c ^ d ^ g ^ j ^ 0x082EFA98EC4E6C89ULL);

    p = mix(p ^ rot(q, 17) ^ rot(r, 31));
    q = mix(q ^ rot(r, 23) ^ rot(t, 41));
    r = mix(r ^ rot(t, 29) ^ rot(p, 37));
    t = mix(t ^ rot(p, 13) ^ rot(q, 47));

    stringstream ss;
    ss << hex << nouppercase << setfill('0') << setw(16) << p << setw(16) << q << setw(16) << r << setw(16) << t;
    string out = ss.str();
    transform(out.begin(), out.end(), out.begin(), [](unsigned char ch){ return char(tolower(ch)); });
    return out;
}

pair<string, int> computeBound(const string& hexStr) {
    string h = hexStr;
    transform(h.begin(), h.end(), h.begin(), [](unsigned char c){ return char(tolower(c)); });
    if (h.empty()) h = "0";
    cpp_int f = parseStdBase(h.size() >= 4 ? h.substr(0, 4) : h, 16);
    cpp_int l = parseStdBase(h.size() >= 4 ? h.substr(h.size() - 4) : h, 16);
    int seedVal = static_cast<int>(((f >> 8) ^ (l & 0xFF) ^ (f & 0xFF) ^ (l >> 8)).convert_to<uint64_t>() & 0xFF);
    string h2 = (h.size() & 1) ? ("0" + h) : h;
    string mh;
    mh.reserve(h2.size());
    for (size_t i = 0; i < h2.size(); i += 2) {
        int val = parseStdBase(h2.substr(i, 2), 16).convert_to<int>();
        int adj = (val - seedVal) & 0xFF;
        stringstream ss;
        ss << hex << nouppercase << setw(2) << setfill('0') << adj;
        mh += ss.str();
    }
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

string diffuseKey(const cpp_int& n) {
    return encodeShift(decodeShift(encodeHex(n), 16) + parseStdBase(encodeShift(n, 16), 16), 16);
}

cpp_int validateState(cpp_int n, cpp_int i = 10) {
    if (n < 0 || i < 0) throw runtime_error("n and i must be >= 0");
    n += 32;
    size_t ln = decStr(n).size();
    cpp_int ten79 = powInt(10, 79);
    while (n < ten79) {
        n *= 3;
        n = n + i;
        i = i + i;
    }
    i = cpp_int(10) * (cpp_int(1) << 163);
    n = parseDec(decStr(n) + string(16, '0') + to_string(ln));
    for (int k = 0; k < 8; ++k) {
        n *= 3;
        n = n + i;
        i = i + i;
    }
    n = parseDec(decStr(n * i) + string(8, '0')) + i;
    string s = decStr(n);
    cpp_int chunkBase = powInt(10, 80);
    cpp_int packBase = powInt(10, 82);
    cpp_int packed = static_cast<unsigned long long>(s.size()) + 1;
    for (size_t j = 0; j < s.size(); j += 80) {
        string chunk = s.substr(j, 80);
        packed = packed * packBase + (cpp_int(chunk.size()) * chunkBase) + parseDec(chunk);
    }
    string left = permutePrefix(decStr(distributeBits(packed)));
    string right = processKey(packed);
    string leftLen = to_string(left.size());
    if (leftLen.size() < 6) leftLen = string(6 - leftLen.size(), '0') + leftLen;
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
    uint64_t seedVal = uint64_t(chrono::high_resolution_clock::now().time_since_epoch().count()) ^ uint64_t(random_device{}());
    DeterministicRng32 r{cpp_int(seedVal)};
    int ln = r.randint(64, 256).convert_to<int>();
    vector<char> s;
    s.reserve(ln);
    for (int i = 0; i < ln; ++i) s.push_back(chars[r.boundValue(62).convert_to<int>()]);
    r.shuffle(s);
    return string(s.begin(), s.end());
}

cpp_int normalizeSeedInput(const string& x) { return encodeTextBlock(x); }
cpp_int normalizeSeedInput(const cpp_int& x) { return encodeTextBlock(decStr(x)); }

struct TraceState {
    cpp_int input;
    cpp_int first;
    cpp_int firstPad;
    cpp_int second;
    cpp_int third;
    cpp_int packedLen;
    cpp_int fourth;
    string left;
    cpp_int mix;
    string right;
    cpp_int value;
};

TraceState traceWideState(const cpp_int& nIn, cpp_int i = 10) {
    if (nIn < 0 || i < 0) throw runtime_error("n and i must be >= 0");
    cpp_int n = nIn + 32;
    cpp_int start = n;
    size_t ln = decStr(n).size();
    cpp_int ten79 = powInt(10, 79);

    while (n < ten79) {
        n *= 3;
        n = n + i;
        i = i + i;
    }
    cpp_int first = n;

    i = cpp_int(10) * (cpp_int(1) << 163);
    n = parseDec(decStr(n) + string(16, '0') + to_string(ln));
    cpp_int firstPad = n;

    for (int k = 0; k < 8; ++k) {
        n *= 3;
        n = n + i;
        i = i + i;
    }
    cpp_int second = n;

    n = parseDec(decStr(n * i) + string(8, '0')) + i;
    cpp_int third = n;

    string s = decStr(n);
    cpp_int chunkBase = powInt(10, 80);
    cpp_int packBase = powInt(10, 82);
    cpp_int packed = static_cast<unsigned long long>(s.size()) + 1;
    for (size_t j = 0; j < s.size(); j += 80) {
        string chunk = s.substr(j, 80);
        packed = packed * packBase + (cpp_int(chunk.size()) * chunkBase) + parseDec(chunk);
    }

    cpp_int packedLen = static_cast<unsigned long long>(s.size());
    cpp_int fourth = packed;
    string left = permutePrefix(decStr(distributeBits(fourth)));
    string right = processKey(fourth);
    cpp_int mix = parseDec(string("1") + leftPad(static_cast<unsigned long long>(left.size()), 6) + left + right);
    cpp_int value = diffuseBits(mix, decStr(fourth));

    return {start, first, firstPad, second, third, packedLen, fourth, left, mix, right, value};
}

string bindState(const TraceState& trace, const string& modeId = "32") {
    vector<string> parts = {
        modeId,
        truncatePrefix(trace.input, 24),
        truncatePrefix(trace.first, 96),
        truncatePrefix(trace.firstPad, 96),
        truncatePrefix(trace.second, 96),
        truncatePrefix(trace.third, 96),
        truncatePrefix(trace.fourth, 96),
        truncatePrefixStr(trace.left, 96),
        truncatePrefix(trace.mix, 96),
        truncatePrefixStr(trace.right, 96),
        truncatePrefix(trace.value, 96)
    };
    string joined;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) joined += "|";
        joined += parts[i];
    }
    string a = fold64(joined);
    string b = computeBound(a).first;
    string c = processKey(decodeShift(b, 16));
    string d = fold64(a + b + c + truncatePrefix(trace.packedLen, 8));
    string e = computeBound(d + a).first;
    return fold64(e + d + b + a);
}

string computeHex(const TraceState& trace, const string& modeId = "333", const string& seedHex = "") {
    string root = seedHex.empty() ? bindState(trace, modeId + "|BASE") : seedHex;
    string a = fold64(root + truncatePrefix(trace.value, 128));
    string b = computeBound(a).first;
    string c = fold64(b + root + truncatePrefix(trace.mix, 128));
    string d = computeBound(c + a).first;
    return (c + d).substr(0, 64);
}

string scheduleText(const vector<tuple<int, char, int>>& sched) {
    string out;
    for (const auto& [pos, ch, val] : sched) {
        out += leftPad(pos, 2);
        out.push_back(ch);
        out += leftPad(val, 2);
    }
    return out;
}

vector<tuple<int, char, int>> deriveInjection(const TraceState& trace, const string& baseHexStr, int count = 8, const string& modeId = "333", const string& seedHex = "") {
    if (count < 1 || count > 8) throw runtime_error("count must be in 1..8");
    int totalLen = 64 + count;
    string aux = deriveAuxCharset();
    vector<int> avail(totalLen);
    for (int i = 0; i < totalLen; ++i) avail[i] = i;
    string state = seedHex.empty() ? bindState(trace, modeId + "|LOTTERY") : seedHex;
    vector<tuple<int, char, int>> sched;
    for (int i = 0; i < count; ++i) {
        string posSeed = fold64("POS|" + to_string(i) + "|" + state + "|" + truncatePrefixStr(trace.left, 96) + "|" + baseHexStr);
        string valSeed = fold64("VAL|" + to_string(i) + "|" + state + "|" + truncatePrefixStr(trace.right, 96) + "|" + baseHexStr);
        int pick = (decodeShift(posSeed, 16) % avail.size()).convert_to<int>();
        int pos = avail[pick];
        avail.erase(avail.begin() + pick);
        int val = (decodeShift(valSeed, 16) % aux.size()).convert_to<int>();
        char ch = aux[val];
        sched.push_back({pos, ch, val});
        state = fold64("ROUND|" + to_string(i) + "|" + state + "|" + to_string(pos) + "|" + to_string(val) + "|" + truncatePrefix(trace.mix, 96) + "|" + baseHexStr);
    }
    return sched;
}

string distributeSymbols(const string& baseHexStr, const vector<tuple<int, char, int>>& sched, int count = 8) {
    int totalLen = 64 + count;
    string out(totalLen, '\0');
    for (const auto& [pos, ch, _] : sched) out[pos] = ch;
    int j = 0;
    for (int i = 0; i < totalLen; ++i) if (out[i] == '\0') out[i] = baseHexStr[j++];
    return out;
}

string computeTraceExtended(const TraceState& trace, int count = 8) {
    string root = bindState(trace, "333|ROOT");
    string bodyB = computeHex(trace, "333|BASE", root);
    auto pepperB = deriveInjection(trace, bodyB, count, "333|LOTTERY", root);
    string raw = distributeSymbols(bodyB, pepperB, count);
    string rebound = fold64(root + raw + scheduleText(pepperB) + truncatePrefix(trace.first, 96));
    string body = computeHex(trace, "333|BASE2", rebound);
    auto pepper = deriveInjection(trace, body, count, "333|LOTTERY2", rebound);
    return distributeSymbols(body, pepper, count);
}

string generatePrimaryKey() { return computeKeyDigest(normalizeSeedInput(generateSeedSource())).first; }
string generatePrimaryKey(const string& x) { return computeKeyDigest(normalizeSeedInput(x)).first; }
string generatePrimaryKey(const cpp_int& x) { return computeKeyDigest(normalizeSeedInput(x)).first; }

string generateExtendedKey() { return computeTraceExtended(traceWideState(normalizeSeedInput(generateSeedSource())), 8); }
string generateExtendedKey(const string& x, int count = 8) { return computeTraceExtended(traceWideState(normalizeSeedInput(x)), count); }
string generateExtendedKey(const cpp_int& x, int count = 8) { return computeTraceExtended(traceWideState(normalizeSeedInput(x)), count); }

string generateKey(int mode = 0, int count = 8) {
    return mode == 0 ? generatePrimaryKey() : generateExtendedKey();
}

string generateKey(const string& x, int mode = 0, int count = 8) {
    return mode == 0 ? generatePrimaryKey(x) : generateExtendedKey(x, count);
}

string generateKey(const cpp_int& x, int mode = 0, int count = 8) {
    return mode == 0 ? generatePrimaryKey(x) : generateExtendedKey(x, count);
}

int main(int argc, char* argv[]) {
    bool hasText = false;
    string textValue;
    bool hasStart = false;
    bool hasEnd = false;
    long long start = 0;
    long long end = 0;
    int mode = 0;
    int count = 8;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--text" && i + 1 < argc) {
            hasText = true;
            textValue = argv[++i];
        } else if (arg == "--start" && i + 1 < argc) {
            hasStart = true;
            start = stoll(argv[++i]);
        } else if (arg == "--end" && i + 1 < argc) {
            hasEnd = true;
            end = stoll(argv[++i]);
        } else if (arg == "--mode" && i + 1 < argc) {
            mode = stoi(argv[++i]);
        } else if (arg == "--count" && i + 1 < argc) {
            count = stoi(argv[++i]);
        }
    }

    if (hasText) {
        cout << generateKey(textValue, mode, count) << '\n';
        return 0;
    }

    if (hasStart && hasEnd && end >= start) {
        for (long long i = start; i <= end; ++i) {
            cout << i << " = " << generateKey(cpp_int(i), mode, count) << '\n';
        }
        return 0;
    }

    cout << generateKey(mode, count) << '\n';
    return 0;
}
