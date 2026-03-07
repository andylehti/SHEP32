#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <random>

using namespace std;
using boost::multiprecision::cpp_int;

const string gCharBase = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`\"',_!#";

string gChar(size_t c) { return gCharBase.substr(0, c); }

cpp_int parseDec(const string& s) {
    if (s.empty()) throw runtime_error("empty decimal string");
    cpp_int out = 0;
    for (char ch : s) {
        if (ch < '0' || ch > '9') throw runtime_error("bad decimal digit");
        out = out * 10 + (ch - '0');
    }
    return out;
}

cpp_int parseStdBase(const string& s, int base) {
    if (s.empty()) throw runtime_error("empty parse string");
    cpp_int out = 0;
    for (char ch : s) {
        int v = 0;
        if (ch >= '0' && ch <= '9') v = ch - '0';
        else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
        else throw runtime_error("bad digit");
        if (v >= base) throw runtime_error("digit out of range");
        out = out * base + v;
    }
    return out;
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

string hexLower(const cpp_int& n) {
    if (n == 0) return "0";
    stringstream ss;
    ss << std::hex << n;
    string s = ss.str();
    transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return char(tolower(c)); });
    return s;
}

string binStr(const cpp_int& n) {
    if (n == 0) return "0";
    cpp_int x = n;
    string out;
    while (x > 0) {
        out.push_back((x & 1) ? '1' : '0');
        x >>= 1;
    }
    reverse(out.begin(), out.end());
    return out;
}

string binTail(const cpp_int& n) {
    string b = binStr(n);
    return b.size() <= 1 ? "" : b.substr(1);
}

bool isHex64(const string& k) {
    if (k.size() != 64) return false;
    for (char ch : k) {
        unsigned char o = static_cast<unsigned char>(ch);
        if (!((o >= '0' && o <= '9') || (o >= 'A' && o <= 'F') || (o >= 'a' && o <= 'f'))) return false;
    }
    return true;
}

vector<string> fastAnyBaseList(cpp_int val, int b) {
    if (val == 0) return {"0"};
    vector<string> out;
    cpp_int x = val;
    while (x > 0) {
        cpp_int rem = x % b;
        x /= b;
        out.push_back(rem.convert_to<string>());
    }
    reverse(out.begin(), out.end());
    return out;
}

cpp_int fromAnyBase(const vector<string>& parts, int b) {
    cpp_int res = 0;
    for (const auto& p : parts) res = res * b + parseDec(p);
    return res;
}

string fastBaseConvert(cpp_int val, int b, size_t padTo, const string& charset) {
    string out(padTo, charset[0]);
    for (size_t i = 0; i < padTo; ++i) {
        cpp_int rem = val % b;
        val /= b;
        out[padTo - 1 - i] = charset[rem.convert_to<unsigned long long>()];
    }
    return out;
}

cpp_int tDecimal(const string& c, int b) {
    string s = c;
    size_t l = s.size();
    if (b == 10) {
        cpp_int v = parseDec(s);
        cpp_int add = l > 1 ? (powInt(10, l) - 10) / 9 : 0;
        return v + add;
    }
    if (b == 16) {
        cpp_int v = parseStdBase(s, 16);
        cpp_int add = l > 1 ? (powInt(16, l) - 16) / 15 : 0;
        return v + add;
    }
    unordered_map<char,int> charMap;
    string chars = gChar(b);
    for (int i = 0; i < b; ++i) charMap[chars[i]] = i;
    cpp_int v = 0;
    for (char ch : s) v = v * b + charMap[ch];
    cpp_int geomSum = (b > 1 && l > 1) ? (powInt(b, l) - b) / (b - 1) : ((b == 1 && l > 1) ? cpp_int(l - 1) : cpp_int(0));
    return v + geomSum;
}

string fDecimal(const cpp_int& d, int b) {
    string c = gChar(b);
    if (b == 1) return string((d + 1).convert_to<size_t>(), c[0]);
    cpp_int target = d * (b - 1) + b;
    size_t n = 0;
    cpp_int cur = b;
    while (cur <= target) {
        ++n;
        cur *= b;
    }
    cpp_int geomSum = n > 0 ? (powInt(b, n) - b) / (b - 1) : 0;
    cpp_int r = d - geomSum;
    return n == 0 ? "" : fastBaseConvert(r, b, n, c);
}

class DeterministicRng32 {
public:
    int n = 624;
    int m = 397;
    uint32_t matrixA = 0x9908b0df;
    uint32_t upperMask = 0x80000000;
    uint32_t lowerMask = 0x7fffffff;
    vector<uint32_t> mt;
    int mti;

    explicit DeterministicRng32(const cpp_int& seedValue = 1) : mt(n, 0), mti(n + 1) { setSeed(seedValue); }

    void setSeed(cpp_int seedValue) {
        if (seedValue < 0) seedValue = -seedValue;
        vector<uint32_t> key;
        cpp_int x = seedValue;
        while (x > 0) {
            key.push_back(static_cast<uint32_t>((x & 0xFFFFFFFF).convert_to<uint64_t>()));
            x >>= 32;
        }
        if (key.empty()) key.push_back(0);
        initByArray(key);
    }

    void initGenrand(uint32_t s) {
        mt[0] = s & 0xFFFFFFFFu;
        for (int i = 1; i < n; ++i) mt[i] = (1812433253u * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFFu;
        mti = n;
    }

    void initByArray(const vector<uint32_t>& initKey) {
        initGenrand(19650218u);
        int i = 1;
        int j = 0;
        int keyLength = static_cast<int>(initKey.size());
        for (int k = max(n, keyLength); k > 0; --k) {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1664525u)) + initKey[j] + j;
            mt[i] &= 0xFFFFFFFFu;
            ++i; ++j;
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

    uint32_t nextU32() {
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

    cpp_int getRandBits(int k) {
        if (k <= 0) return 0;
        int words = (k + 31) / 32;
        cpp_int x = 0;
        for (int i = 0; i < words; ++i) x = (x << 32) | nextU32();
        int extra = words * 32 - k;
        if (extra) x >>= extra;
        return x;
    }

    cpp_int randBelow(const cpp_int& nVal) {
        if (nVal <= 0) throw runtime_error("n must be > 0");
        int k = boost::multiprecision::msb(nVal) + 1;
        while (true) {
            cpp_int r = getRandBits(k);
            if (r < nVal) return r;
        }
    }

    cpp_int randint(const cpp_int& a, const cpp_int& b) {
        if (a > b) throw runtime_error("a must be <= b");
        return a + randBelow(b - a + 1);
    }

    template <typename T>
    void shuffle(vector<T>& arr) {
        for (int i = static_cast<int>(arr.size()) - 1; i > 0; --i) {
            int j = randBelow(i + 1).convert_to<int>();
            swap(arr[i], arr[j]);
        }
    }
};

int hexNibble(char c) {
    unsigned char o = static_cast<unsigned char>(c);
    if (o >= '0' && o <= '9') return o - '0';
    if (o >= 'a' && o <= 'f') return o - 'a' + 10;
    if (o >= 'A' && o <= 'F') return o - 'A' + 10;
    throw runtime_error("non-hex");
}

vector<int> hexToNibbles(const string& h) {
    if (h.size() != 64) throw runtime_error("keyHex must be 64 hex chars");
    vector<int> out;
    for (char c : h) out.push_back(hexNibble(c));
    return out;
}

int64_t lcg(int64_t x) { return (48271LL * (x % 2147483647LL)) % 2147483647LL; }

vector<int> idx(int n, int64_t s) {
    vector<int> r(n);
    for (int i = 0; i < n; ++i) r[i] = i;
    int64_t x = s ? s : 1;
    for (int i = n - 1; i > 0; --i) {
        x = lcg(x);
        int j = static_cast<int>(x % (i + 1));
        swap(r[i], r[j]);
    }
    return r;
}

string permuteBySeed(const string& t, int64_t s) {
    if (t.size() < 2) return t;
    auto r = idx(static_cast<int>(t.size()), s);
    string out;
    out.reserve(t.size());
    for (int i : r) out.push_back(t[i]);
    return out;
}

string unpermuteBySeed(const string& t, int64_t s) {
    if (t.size() < 2) return t;
    auto r = idx(static_cast<int>(t.size()), s);
    vector<int> inv(t.size());
    for (int p = 0; p < static_cast<int>(t.size()); ++p) inv[r[p]] = p;
    string out(t.size(), '\0');
    for (int i = 0; i < static_cast<int>(t.size()); ++i) out[i] = t[inv[i]];
    return out;
}

vector<int64_t> deriveSeeds(const string& keyHex, int steps) {
    auto nibbles = hexToNibbles(keyHex);
    int64_t m = 2147483647LL;
    int64_t acc = 1;
    int64_t cum = 0;
    vector<int64_t> out(steps, 0);
    for (int i = 0; i < steps; ++i) {
        int v = nibbles[i % static_cast<int>(nibbles.size())];
        acc = (acc * 131 + v + 1) % m;
        cum = (cum + acc + (i + 1) * 17) % m;
        out[i] = cum ? cum : 1;
    }
    return out;
}

string generateSeries(const cpp_int& s, int n) {
    DeterministicRng32 r(s);
    string out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) out.push_back(char('0' + r.randint(0, 8).convert_to<int>()));
    return out;
}

string manipulateData(const string& s, const cpp_int& c) {
    string k = generateSeries(c, static_cast<int>(s.size()));
    string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) out.push_back(char((((s[i] + k[i] - 96) % 10) + 48)));
    return out;
}

string inverseData(const string& s, const cpp_int& c) {
    string k = generateSeries(c, static_cast<int>(s.size()));
    string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) out.push_back(char((((s[i] - k[i]) % 10 + 10) % 10) + 48));
    return out;
}

string qRotate(const string& s) {
    string mid = s.substr(2, 3);
    reverse(mid.begin(), mid.end());
    return s.substr(5) + mid + s.substr(0, 2);
}

string pRotate(const string& s) {
    string mid = s.substr(s.size() - 5, 3);
    reverse(mid.begin(), mid.end());
    return s.substr(s.size() - 2) + mid + s.substr(0, s.size() - 5);
}

string interject(const string& s) {
    string core = s;
    string p;
    if (s.size() % 2) {
        core = s.substr(0, s.size() - 1);
        p = s.substr(s.size() - 1);
    }
    size_t h = core.size() / 2;
    string out;
    out.reserve(s.size());
    for (size_t i = 0; i < h; ++i) {
        out.push_back(core[i]);
        out.push_back(core[h + i]);
    }
    return out + p;
}

string inverJect(const string& s) {
    string core = s;
    string p;
    if (s.size() % 2) {
        core = s.substr(0, s.size() - 1);
        p = s.substr(s.size() - 1);
    }
    string a, b;
    for (size_t i = 0; i < core.size(); i += 2) a.push_back(core[i]);
    for (size_t i = 1; i < core.size(); i += 2) b.push_back(core[i]);
    return a + b + p;
}

cpp_int bSplit(const cpp_int& s, int f = 4) {
    string b = binTail(s);
    int l = static_cast<int>(b.size());
    int rem = l % f;
    string out = "1";
    for (int i = 0; i < l - rem; i += f) {
        string chunk = b.substr(i, f);
        reverse(chunk.begin(), chunk.end());
        out += chunk;
    }
    if (rem) out += b.substr(l - rem);
    return parseStdBase(out, 2);
}

cpp_int kSplit(const cpp_int& s, const string& k) {
    string sBin = binTail(s);
    string kStr;
    for (char ch : k) if (ch != '0') kStr.push_back(ch);
    if (kStr.empty()) return parseStdBase("1" + string(sBin.rbegin(), sBin.rend()), 2);
    vector<int> kDigits;
    for (char d : kStr) kDigits.push_back((d - '0') + 1);
    vector<string> chunks;
    int idxPos = 0;
    int kIdx = 0;
    while (idxPos < static_cast<int>(sBin.size())) {
        int step = kDigits[kIdx % static_cast<int>(kDigits.size())];
        string chunk = sBin.substr(idxPos, step);
        reverse(chunk.begin(), chunk.end());
        chunks.push_back(chunk);
        idxPos += step;
        ++kIdx;
    }
    string out = "1";
    for (const auto& c : chunks) out += c;
    return parseStdBase(out, 2);
}

cpp_int keySplit(cpp_int n, const cpp_int& k, int y = 1) {
    string m = decStr(k);
    if (y != 1) reverse(m.begin(), m.end());
    for (char d : m) n = bSplit(n, (d - '0') + 2);
    return n;
}

cpp_int baseSplit(const cpp_int& n, const cpp_int& k, int b = 8, int y = 1) {
    int m = 1 << 16;
    vector<string> nDigits = fastAnyBaseList(n, b);
    vector<string> z;
    for (const auto& x : fastAnyBaseList(k, m)) if (x.size() >= 2 && x.size() <= 10) z.push_back(x);
    if (z.empty()) z.push_back(decStr((k % (m - 2)) + 2));
    size_t cap = (nDigits.size() + 2) * 40;
    size_t loops = 0;
    size_t targetLen = y == 1 ? nDigits.size() + 1 : nDigits.size();
    while (z.size() < targetLen) {
        cpp_int nextK = parseDec(z.back()) + m;
        for (const auto& x : fastAnyBaseList(nextK, m)) if (x.size() >= 2 && x.size() <= 10) z.push_back(x);
        ++loops;
        if (loops > cap) break;
    }
    while (z.size() < targetLen) z.push_back(z.back());
    if (y == 1) {
        int guard = (1 - (stoi(z[0]) % b)) % b;
        vector<string> digits;
        digits.push_back(to_string(guard));
        digits.insert(digits.end(), nDigits.begin(), nDigits.end());
        vector<string> outDigits;
        for (size_t i = 0; i < digits.size(); ++i) outDigits.push_back(to_string((stoi(digits[i]) + stoi(z[i])) % b));
        return fromAnyBase(outDigits, b);
    }
    vector<string> outDigits;
    for (size_t i = 0; i < nDigits.size(); ++i) outDigits.push_back(to_string((stoi(nDigits[i]) - stoi(z[i]) + b * 1000) % b));
    if (outDigits.size() <= 1) return 0;
    return fromAnyBase(vector<string>(outDigits.begin() + 1, outDigits.end()), b);
}

string Ap(const string& n, const string& m, size_t p) { return decStr(parseDec(n) * parseDec(m)).substr(0, p); }

string Bp(const string& n, size_t p) {
    int n0 = n[0] - '0';
    string out;
    out.reserve(p);
    for (size_t i = 0; i < p; ++i) out.push_back(char((((n[i % n.size()] - '0' + n0) % 10) + '0')));
    return out;
}

string Cp(const string& n, const string& m, size_t p) {
    size_t take = 3 % n.size();
    string left = n.substr(0, take);
    return decStr(parseDec(n) * parseDec(left)).substr(0, p);
}

string Dp(const string& n, const string& m, size_t p) {
    string out;
    for (size_t i = 0; out.size() < p; ++i) out += to_string(abs((n[i % n.size()] - '0') * (m[i % m.size()] - '0')));
    return out.substr(0, p);
}

const array<array<cpp_int, 10>, 10> epTbl = {{
    {{parseDec("14159265358979312"), parseDec("5707963267948966"), parseDec("4719755119659763"), parseDec("7853981633974483"), parseDec("6283185307179586"), parseDec("5235987755982988"), parseDec("4487989505128276"), parseDec("39269908169872414"), parseDec("3490658503988659"), parseDec("3141592653589793")}},
    {{parseDec("5707963267948966"), parseDec("7853981633974483"), parseDec("5235987755982988"), parseDec("39269908169872414"), parseDec("3141592653589793"), parseDec("2617993877991494"), parseDec("2243994752564138"), parseDec("19634954084936207"), parseDec("17453292519943295"), parseDec("15707963267948966")}},
    {{parseDec("4719755119659763"), parseDec("5235987755982988"), parseDec("3490658503988659"), parseDec("2617993877991494"), parseDec("20943951023931953"), parseDec("17453292519943295"), parseDec("14959965017094254"), parseDec("1308996938995747"), parseDec("11635528346628864"), parseDec("10471975511965977")}},
    {{parseDec("7853981633974483"), parseDec("39269908169872414"), parseDec("2617993877991494"), parseDec("19634954084936207"), parseDec("15707963267948966"), parseDec("1308996938995747"), parseDec("1121997376282069"), parseDec("9817477042468103"), parseDec("8726646259971647"), parseDec("7853981633974483")}},
    {{parseDec("6283185307179586"), parseDec("3141592653589793"), parseDec("20943951023931953"), parseDec("15707963267948966"), parseDec("12566370614359174"), parseDec("10471975511965977"), parseDec("8975979010256552"), parseDec("7853981633974483"), parseDec("6981317007977318"), parseDec("6283185307179587")}},
    {{parseDec("5235987755982988"), parseDec("2617993877991494"), parseDec("17453292519943295"), parseDec("1308996938995747"), parseDec("10471975511965977"), parseDec("8726646259971647"), parseDec("7479982508547127"), parseDec("6544984694978735"), parseDec("5817764173314432"), parseDec("5235987755982988")}},
    {{parseDec("4487989505128276"), parseDec("2243994752564138"), parseDec("14959965017094254"), parseDec("1121997376282069"), parseDec("8975979010256552"), parseDec("7479982508547127"), parseDec("641141357875468"), parseDec("5609986881410345"), parseDec("49866550056980846"), parseDec("4487989505128276")}},
    {{parseDec("39269908169872414"), parseDec("19634954084936207"), parseDec("1308996938995747"), parseDec("9817477042468103"), parseDec("7853981633974483"), parseDec("6544984694978735"), parseDec("5609986881410345"), parseDec("4908738521234052"), parseDec("4363323129985824"), parseDec("39269908169872414")}},
    {{parseDec("3490658503988659"), parseDec("17453292519943295"), parseDec("11635528346628864"), parseDec("8726646259971647"), parseDec("6981317007977318"), parseDec("5817764173314432"), parseDec("49866550056980846"), parseDec("4363323129985824"), parseDec("38785094488762877"), parseDec("3490658503988659")}},
    {{parseDec("3141592653589793"), parseDec("15707963267948966"), parseDec("10471975511965977"), parseDec("7853981633974483"), parseDec("6283185307179587"), parseDec("5235987755982988"), parseDec("4487989505128276"), parseDec("39269908169872414"), parseDec("3490658503988659"), parseDec("31415926535897934")}}
}};

string Ep(const string& n, size_t p) {
    cpp_int total = 0;
    for (size_t i = 0; i < p; ++i) total += epTbl[n[i % n.size()] - '0'][n[(i + 1) % n.size()] - '0'];
    string out = decStr(total);
    return out.size() <= p ? out : out.substr(out.size() - p);
}

string processKey(const cpp_int& nIn, cpp_int mIn = 0) {
    string n = decStr(nIn);
    string m = mIn == 0 ? n : decStr(mIn);
    size_t p = n.size();
    int r = n[0] - '0';
    int t = m.size() > static_cast<size_t>(n[0] - '0') ? n[(m[n[0] - '0'] - '0') % p] - '0' : n.back() - '0';
    int a = (r + t) % 6;
    int b = (r - t) % 6;
    if (b < 0) b += 6;
    string combo = Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p);
    n = a == 0 ? Ap(n, m, p) : a == 1 ? Bp(n, p) : a == 2 ? Cp(n, m, p) : a == 3 ? Dp(n, m, p) : a == 4 ? Ep(n, p) : combo;
    combo = Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p);
    n = b == 0 ? Cp(n, m, p) : b == 1 ? Dp(n, m, p) : b == 2 ? combo : b == 3 ? Bp(n, p) : b == 4 ? Ap(n, m, p) : combo;
    char aa = '2';
    char bb = '3';
    for (char ch : n) if (isdigit(static_cast<unsigned char>(ch)) && ch != '0') { aa = ch; break; }
    for (size_t i = 1; i < n.size(); ++i) if (isdigit(static_cast<unsigned char>(n[i])) && n[i] != '0') { bb = n[i]; break; }
    n = decStr(bSplit(bSplit(parseDec(n) + parseDec(pRotate(n)))));
    n = decStr(tDecimal(qRotate(n), 10));
    string add = string() + aa + bb + string(p >= 2 ? p - 2 : 0, '0');
    string out = decStr(parseDec(n) + parseDec(add) + parseDec(m));
    return out.size() <= p ? out : out.substr(out.size() - p);
}

cpp_int toBytes(const string& t) {
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

cpp_int checkData(cpp_int n, cpp_int i = 10) {
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
    n = packed;
    string left = qRotate(decStr(bSplit(n)));
    string right = processKey(n);
    string leftLen = to_string(left.size());
    if (leftLen.size() < 6) leftLen = string(6 - leftLen.size(), '0') + leftLen;
    cpp_int mix = parseDec(string("1") + leftLen + left + right);
    return kSplit(mix, decStr(n));
}

string manipulateKey(const cpp_int& n) {
    return fDecimal(tDecimal(hexLower(n), 16) + parseStdBase(fDecimal(n, 16), 16), 16);
}

uint64_t mix64(uint64_t x) {
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}

string fold64(const string& h) {
    string s = h.empty() ? "0" : h;
    uint64_t a = 0x243F6A8885A308D3ULL;
    uint64_t b = 0x13198A2E03707344ULL;
    uint64_t c = 0xA4093822299F31D0ULL;
    uint64_t d = 0x082EFA98EC4E6C89ULL;
    uint64_t n = static_cast<uint64_t>(s.size());
    uint64_t p = 1;
    for (size_t i = 0; i < s.size(); i += 16, ++p) {
        uint64_t x = parseStdBase(s.substr(i, 16), 16).convert_to<uint64_t>();
        x ^= p * 0x9E3779B97F4A7C15ULL;
        x ^= n * 0xC2B2AE3D27D4EB4FULL;
        a = ((a ^ x) * 0x9E3779B185EBCA87ULL);
        b = ((b + x + a) * 0xC2B2AE3D27D4EB4FULL);
        c = ((c ^ (b + x + 0x165667B19E3779F9ULL)) * 0x94D049BB133111EBULL);
        d = ((d + c + (x << 17) + (x >> 47)) * 0xD6E8FEB86659FD93ULL);
    }
    a = mix64(a ^ n);
    b = mix64(b ^ (n << 1));
    c = mix64(c ^ (n << 2));
    d = mix64(d ^ (n << 3));
    uint64_t e = mix64(a ^ c ^ 0x243F6A8885A308D3ULL);
    uint64_t f = mix64(b ^ d ^ 0x13198A2E03707344ULL);
    uint64_t g = mix64(a ^ b ^ c ^ 0xA4093822299F31D0ULL);
    uint64_t j = mix64(a ^ b ^ d ^ 0x082EFA98EC4E6C89ULL);
    stringstream ss;
    ss << hex << nouppercase << setfill('0') << setw(16) << e << setw(16) << f << setw(16) << g << setw(16) << j;
    string out = ss.str();
    transform(out.begin(), out.end(), out.begin(), [](unsigned char ch){ return char(tolower(ch)); });
    return out;
}

int getE(const string& hex64) {
    string x = hex64;
    transform(x.begin(), x.end(), x.begin(), [](unsigned char c){ return char(tolower(c)); });
    if (x.size() < 64) x = string(64 - x.size(), '0') + x;
    if (x.size() > 64) x = x.substr(x.size() - 64);
    string s4 = decStr(parseStdBase(x.substr(0, 4), 16) + parseStdBase(x.substr(60, 4), 16));
    while (s4.size() > 1 && s4[0] == '0') s4.erase(s4.begin());
    if (s4.empty()) s4 = "0";
    if (s4.size() > 4) s4 = s4.substr(0, 4);
    int n = stoi(s4);
    if (n < 4096) return n;
    if (n % 2 == 0) return stoi(s4.substr(0, s4.size() - 1)) + ((s4.size() > 1 && s4[s4.size() - 2] == '0') ? 100 : 0);
    return stoi(s4.substr(1)) + ((s4.size() > 1 && s4[1] == '0') ? 100 : 0);
}

pair<string,int> getB(const string& hexStr) {
    string h = hexStr;
    transform(h.begin(), h.end(), h.begin(), [](unsigned char c){ return char(tolower(c)); });
    if (h.empty()) h = "0";
    cpp_int f = parseStdBase(h.size() >= 4 ? h.substr(0, 4) : h, 16);
    cpp_int l = parseStdBase(h.size() >= 4 ? h.substr(h.size() - 4) : h, 16);
    int seedVal = static_cast<int>(((f >> 8) ^ (l & 0xFF) ^ (f & 0xFF) ^ (l >> 8)).convert_to<uint64_t>() & 0xFF);
    string h2 = (h.size() & 1) ? ("0" + h) : h;
    string mh;
    for (size_t i = 0; i < h2.size(); i += 2) {
        int val = parseStdBase(h2.substr(i, 2), 16).convert_to<int>();
        int adj = (val - seedVal) & 0xFF;
        stringstream ss;
        ss << hex << nouppercase << setw(2) << setfill('0') << adj;
        mh += ss.str();
    }
    mh = hexLower(parseStdBase(mh, 16) + parseStdBase(h, 16));
    cpp_int baseParam = parseStdBase(mh.size() >= 4 ? mh.substr(0, 4) : mh, 16);
    cpp_int nVal = parseStdBase(mh, 16);
    cpp_int kVal = parseStdBase(mh.size() >= 4 ? mh.substr(mh.size() - 4) : mh, 16);
    cpp_int splitVal = baseSplit(nVal, kVal, ((baseParam & 4096) + 64).convert_to<int>(), 1);
    string splitHex = hexLower(splitVal);
    string s = fold64(h + mh + splitHex);
    return {s, getE(s)};
}

string getKey(cpp_int n, size_t x = 78) {
    while (true) {
        n = (n / 8) + parseDec(Ep(decStr(n / 5), decStr(n).size()));
        string s = decStr(n);
        if (s.size() <= x) return s;
    }
}

string fetchKey(const cpp_int& n) {
    cpp_int checked = checkData(n + 90, (n % 7) + 1);
    string key = getKey(checked, 79);
    return manipulateKey(tDecimal(manipulateData(key, n), 10));
}

pair<string,int> hashKey(const cpp_int& n) {
    cpp_int a = parseStdBase(fetchKey(n) + hexLower(n), 16);
    return getB(fetchKey(a));
}

string generatePKey() {
    string chars = gChar(62);

    uint64_t seedVal =
        uint64_t(std::chrono::high_resolution_clock::now().time_since_epoch().count()) ^
        uint64_t(std::random_device{}());

    DeterministicRng32 r{cpp_int(seedVal)};
    int ln = r.randint(64, 256).convert_to<int>();

    vector<char> s;
    s.reserve(ln);
    for (int i = 0; i < ln; ++i) {
        s.push_back(chars[r.randBelow(62).convert_to<int>()]);
    }

    r.shuffle(s);

    string base62(s.begin(), s.end());
    return hashKey(tDecimal(base62, 62)).first;
}

string generatePKey(const string& n) {
    return hashKey(toBytes(n)).first;
}

string generatePKey(const cpp_int& n) {
    return hashKey(toBytes(n.convert_to<string>())).first;
}

int main(int argc, char* argv[])
{
    long start = -1;
    long end = -1;
    bool hasText = false;
    string textValue;

    for (int i = 1; i < argc; ++i)
    {
        string arg = argv[i];

        if (arg == "--start" && i + 1 < argc)
        {
            start = std::stol(argv[++i]);
        }
        else if (arg == "--end" && i + 1 < argc)
        {
            end = std::stol(argv[++i]);
        }
        else if (arg == "--text" && i + 1 < argc)
        {
            hasText = true;
            textValue = argv[++i];
        }
    }


    if (hasText)
    {
        cout << generatePKey(textValue) << '\n';
        return 0;
    }

    if (start >= 0 && end >= start)
    {
        for (long i = start; i <= end; ++i)
        {
            cout << i << " = " << generatePKey(to_string(i)) << '\n';
        }
        return 0;
    }

    cout << generatePKey() << '\n';
    return 0;
}