#include "audit.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <openssl/sha.h>

namespace fs = std::filesystem;

namespace shepAudit {

namespace {

struct ProgressBar {
    uint64_t total = 1;
    uint64_t count = 0;
    int width = 34;
    bool enabled = true;
    std::string note;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point last = std::chrono::steady_clock::time_point{};
    bool doneFlag = false;

    explicit ProgressBar(uint64_t totalIn = 1, bool enabledIn = true): total(std::max<uint64_t>(1, totalIn)), enabled(enabledIn), last(start) {}

    void set(const std::string& x) { note = x; }

    void step(uint64_t n = 1, const std::string* x = nullptr, bool force = false) {
        if (!enabled) return;
        count += n;
        if (x) note = *x;
        auto now = std::chrono::steady_clock::now();
        if (!force && count < total && std::chrono::duration<double>(now - last).count() < 0.08) return;
        last = now;
        double frac = std::min<double>(1.0, double(count) / double(total));
        int filled = int(double(width) * frac);
        std::string bar(size_t(filled), '#');
        bar += std::string(size_t(width - filled), '.');
        double elapsed = std::chrono::duration<double>(now - start).count();
        double rate = elapsed > 0.0 ? double(count) / elapsed : 0.0;
        double remain = rate > 0.0 ? double(total - count) / rate : 0.0;
        std::ostringstream ss;
        ss << '\r' << '[' << bar << "] " << std::fixed << std::setprecision(2) << std::setw(6) << (frac * 100.0) << "% "
           << count << '/' << total << ' ' << std::setprecision(1) << std::setw(9) << rate << "/s eta " << std::setw(7) << remain << 's';
        if (!note.empty()) ss << "  " << note;
        std::cerr << ss.str() << std::flush;
        if (count >= total && !doneFlag) {
            doneFlag = true;
            std::cerr << '\n' << std::flush;
        }
    }

    void done(const std::string& x = "") {
        if (!x.empty()) note = x;
        step(0, nullptr, true);
    }
};

bool isMiss(double v) {
    return std::isnan(v);
}

double absBigBitLength(const BigInt& x) {
    BigInt v = x;
    if (v < 0) v = -v;
    if (v == 0) return 0;
    return double(boost::multiprecision::msb(v) + 1);
}

int inferBits(const std::vector<BigInt>& samples) {
    int out = 1;
    for (const auto& x : samples) out = std::max(out, int(absBigBitLength(x)));
    return out;
}

double binEntropy(double p) {
    if (!(p > 0.0 && p < 1.0)) return 0.0;
    double q = 1.0 - p;
    return -(p * std::log2(p) + q * std::log2(q));
}

std::string cleanCell(double v) {
    if (isMiss(v)) return "";
    std::ostringstream ss;
    ss << std::setprecision(17) << v;
    return ss.str();
}

void writeTsv(const std::string& path, const std::vector<std::string>& header, const std::vector<std::vector<std::string>>& rows) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("failed to open tsv for write: " + path);
    for (size_t i = 0; i < header.size(); ++i) {
        if (i) f << '\t';
        f << header[i];
    }
    f << '\n';
    for (const auto& row : rows) {
        for (size_t i = 0; i < row.size(); ++i) {
            if (i) f << '\t';
            f << row[i];
        }
        f << '\n';
    }
}

std::string bigToString(const BigInt& x) {
    return x.convert_to<std::string>();
}

std::vector<TopCell> topCells(const std::vector<std::vector<double>>& mat, size_t count) {
    struct CellPick { double dev; int inBit; int outBit; double rate; };
    std::vector<CellPick> picks;
    for (int i = 0; i < int(mat.size()); ++i) {
        for (int j = 0; j < int(mat[i].size()); ++j) picks.push_back({std::abs(mat[i][j] - 0.5), i, j, mat[i][j]});
    }
    if (picks.empty()) return {};
    count = std::max<size_t>(1, std::min(count, picks.size()));
    std::nth_element(picks.begin(), picks.end() - std::ptrdiff_t(count), picks.end(), [](const CellPick& a, const CellPick& b){ return a.dev < b.dev; });
    std::vector<CellPick> top(picks.end() - std::ptrdiff_t(count), picks.end());
    std::sort(top.begin(), top.end(), [](const CellPick& a, const CellPick& b){ return a.dev > b.dev; });
    std::vector<TopCell> out;
    out.reserve(top.size());
    for (size_t i = 0; i < top.size(); ++i) out.push_back({int(i + 1), top[i].inBit, top[i].outBit, top[i].rate, top[i].dev});
    return out;
}

HashBytes32 hexToBytes32(const std::string& hex) {
    auto nib = [](char ch) -> uint8_t {
        if (ch >= '0' && ch <= '9') return uint8_t(ch - '0');
        if (ch >= 'a' && ch <= 'f') return uint8_t(ch - 'a' + 10);
        if (ch >= 'A' && ch <= 'F') return uint8_t(ch - 'A' + 10);
        throw std::runtime_error("invalid hex digit");
    };
    if (hex.size() != 64) throw std::runtime_error("expected 64 hex chars");
    HashBytes32 out{};
    for (size_t i = 0; i < 32; ++i) out[i] = uint8_t((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    return out;
}

uint64_t popcount64(uint64_t x) {
#if defined(__GNUG__) || defined(__clang__)
    return uint64_t(__builtin_popcountll(x));
#else
    uint64_t c = 0;
    while (x) { x &= (x - 1); ++c; }
    return c;
#endif
}

double meanOf(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    double s = std::accumulate(v.begin(), v.end(), 0.0);
    return s / double(v.size());
}

double stdOf(const std::vector<double>& v, double mean) {
    if (v.empty()) return 0.0;
    double s = 0.0;
    for (double x : v) {
        double d = x - mean;
        s += d * d;
    }
    return std::sqrt(s / double(v.size()));
}

std::string fmtNum(double v, int digits, bool fixed) {
    if (isMiss(v)) return "";
    std::ostringstream ss;
    if (fixed) ss << std::fixed;
    ss << std::setprecision(digits) << v;
    return ss.str();
}

std::string fmtAny(double v, int digits, bool fixed) {
    return fmtNum(v, digits, fixed);
}

std::vector<BigInt> resolveSamples(const Options& opts) {
    if (!opts.samples.empty()) return opts.samples;
    return makeRange(opts.start, opts.count);
}

RunResult runHashAuditInternal(const HashBytesFn& hashFn, const std::vector<BigInt>& samples, int maxBits, const std::string& outDir, const std::string& tag, bool deep, ProgressBar* progress, size_t topCount) {
    if (samples.empty()) throw std::runtime_error("no samples provided");
    if (maxBits <= 0) maxBits = inferBits(samples);

    const int sampleCount = int(samples.size());
    std::vector<HashBytes32> baseArr((size_t)sampleCount);
    std::vector<std::vector<double>> infMat(size_t(maxBits), std::vector<double>(256, 0.0));
    std::vector<std::vector<double>> pairMeanMat = deep ? std::vector<std::vector<double>>(size_t(maxBits), std::vector<double>(256, std::numeric_limits<double>::quiet_NaN())) : std::vector<std::vector<double>>();
    std::vector<RowStat> rowStats;
    rowStats.reserve(size_t(maxBits));

    if (progress) progress->set(tag + " base");
    for (int i = 0; i < sampleCount; ++i) {
        baseArr[size_t(i)] = hashFn(samples[size_t(i)]);
        if (progress) progress->step();
    }

    std::vector<HashBytes32> flipArr((size_t)sampleCount);

    for (int inBit = 0; inBit < maxBits; ++inBit) {
        BigInt mask = BigInt(1) << inBit;
        if (progress) progress->set(tag + " bit " + std::to_string(inBit + 1) + "/" + std::to_string(maxBits));

        std::array<uint32_t, 256> counts{};
        std::vector<std::vector<uint64_t>> bitsets;
        size_t wordCount = (samples.size() + 63u) / 64u;
        if (deep) bitsets.assign(256, std::vector<uint64_t>(wordCount, 0));

        for (int i = 0; i < sampleCount; ++i) {
            flipArr[size_t(i)] = hashFn(samples[size_t(i)] ^ mask);
            const auto& a = baseArr[size_t(i)];
            const auto& b = flipArr[size_t(i)];
            for (int byte = 0; byte < 32; ++byte) {
                uint8_t x = uint8_t(a[size_t(byte)] ^ b[size_t(byte)]);
                for (int bit = 0; bit < 8; ++bit) {
                    int outBit = byte * 8 + bit;
                    bool one = ((x >> (7 - bit)) & 1u) != 0u;
                    if (!one) continue;
                    ++counts[size_t(outBit)];
                    if (deep) bitsets[size_t(outBit)][size_t(i) >> 6] |= (uint64_t(1) << (size_t(i) & 63u));
                }
            }
            if (progress) progress->step();
        }

        std::vector<double> p(256), d(256), e(256);
        for (int outBit = 0; outBit < 256; ++outBit) {
            p[size_t(outBit)] = double(counts[size_t(outBit)]) / double(sampleCount);
            d[size_t(outBit)] = std::abs(p[size_t(outBit)] - 0.5);
            e[size_t(outBit)] = binEntropy(p[size_t(outBit)]);
            infMat[size_t(inBit)][size_t(outBit)] = p[size_t(outBit)];
        }

        double pairMeanAbs = std::numeric_limits<double>::quiet_NaN();
        double pairRmsAbs = std::numeric_limits<double>::quiet_NaN();
        double pairMaxAbs = std::numeric_limits<double>::quiet_NaN();

        if (deep) {
            std::vector<double> pairSum(256, 0.0);
            double globalAbsSum = 0.0;
            double globalSqSum = 0.0;
            double globalMax = 0.0;
            uint64_t pairCount = 0;
            for (int i = 0; i < 256; ++i) {
                for (int j = i + 1; j < 256; ++j) {
                    uint64_t co = 0;
                    for (size_t w = 0; w < wordCount; ++w) co += popcount64(bitsets[size_t(i)][w] & bitsets[size_t(j)][w]);
                    double joint = double(co) / double(sampleCount);
                    double indep = joint - (p[size_t(i)] * p[size_t(j)]);
                    double a = std::abs(indep);
                    pairSum[size_t(i)] += a;
                    pairSum[size_t(j)] += a;
                    globalAbsSum += a;
                    globalSqSum += indep * indep;
                    globalMax = std::max(globalMax, a);
                    ++pairCount;
                }
            }
            for (int i = 0; i < 256; ++i) pairMeanMat[size_t(inBit)][size_t(i)] = pairSum[size_t(i)] / 255.0;
            pairMeanAbs = pairCount ? globalAbsSum / double(pairCount) : std::numeric_limits<double>::quiet_NaN();
            pairRmsAbs = pairCount ? std::sqrt(globalSqSum / double(pairCount)) : std::numeric_limits<double>::quiet_NaN();
            pairMaxAbs = pairCount ? globalMax : std::numeric_limits<double>::quiet_NaN();
        }

        double rowMean = meanOf(p);
        double rowStd = stdOf(p, rowMean);
        double rowMeanDev = meanOf(d);
        double rmsSum = 0.0;
        for (double x : p) {
            double z = x - 0.5;
            rmsSum += z * z;
        }
        double rowRmsDev = std::sqrt(rmsSum / double(p.size()));
        double rowMaxDev = *std::max_element(d.begin(), d.end());
        double rowMin = *std::min_element(p.begin(), p.end());
        double rowMax = *std::max_element(p.begin(), p.end());
        double rowMeanEntropy = meanOf(e);
        double rowMinEntropy = *std::min_element(e.begin(), e.end());

        rowStats.push_back({inBit, sampleCount, rowMean, rowStd, rowMeanDev, rowRmsDev, rowMaxDev, rowMin, rowMax, rowMeanEntropy, rowMinEntropy, pairMeanAbs, pairRmsAbs, pairMaxAbs});
    }

    std::vector<ColStat> colStats;
    colStats.reserve(256);
    for (int outBit = 0; outBit < 256; ++outBit) {
        std::vector<double> col((size_t)maxBits);
        std::vector<double> d((size_t)maxBits);
        std::vector<double> e((size_t)maxBits);
        for (int inBit = 0; inBit < maxBits; ++inBit) {
            col[size_t(inBit)] = infMat[size_t(inBit)][size_t(outBit)];
            d[size_t(inBit)] = std::abs(col[size_t(inBit)] - 0.5);
            e[size_t(inBit)] = binEntropy(col[size_t(inBit)]);
        }
        double colMean = meanOf(col);
        double colStd = stdOf(col, colMean);
        double rms = 0.0;
        for (double x : col) {
            double z = x - 0.5;
            rms += z * z;
        }
        colStats.push_back({outBit, maxBits, colMean, colStd, meanOf(d), std::sqrt(rms / double(col.size())), *std::max_element(d.begin(), d.end()), *std::min_element(col.begin(), col.end()), *std::max_element(col.begin(), col.end()), meanOf(e), *std::min_element(e.begin(), e.end())});
    }

    std::vector<double> valid;
    valid.reserve(size_t(maxBits) * 256u);
    std::vector<double> validDev;
    validDev.reserve(valid.capacity());
    std::vector<double> validEntropy;
    validEntropy.reserve(valid.capacity());
    int worstInBit = 0, worstOutBit = 0;
    double worstDev = -1.0;
    double worstRate = 0.0;
    for (int i = 0; i < maxBits; ++i) {
        for (int j = 0; j < 256; ++j) {
            double v = infMat[size_t(i)][size_t(j)];
            double dv = std::abs(v - 0.5);
            valid.push_back(v);
            validDev.push_back(dv);
            validEntropy.push_back(binEntropy(v));
            if (dv > worstDev) {
                worstDev = dv;
                worstInBit = i;
                worstOutBit = j;
                worstRate = v;
            }
        }
    }

    int worstRowMaxIx = 0, worstRowMeanIx = 0, worstColMaxIx = 0, worstColMeanIx = 0;
    for (int i = 1; i < maxBits; ++i) {
        if (rowStats[size_t(i)].maxAbsDevFromHalf > rowStats[size_t(worstRowMaxIx)].maxAbsDevFromHalf) worstRowMaxIx = i;
        if (rowStats[size_t(i)].meanAbsDevFromHalf > rowStats[size_t(worstRowMeanIx)].meanAbsDevFromHalf) worstRowMeanIx = i;
    }
    for (int j = 1; j < 256; ++j) {
        if (colStats[size_t(j)].colMaxAbsDevFromHalf > colStats[size_t(worstColMaxIx)].colMaxAbsDevFromHalf) worstColMaxIx = j;
        if (colStats[size_t(j)].colMeanAbsDevFromHalf > colStats[size_t(worstColMeanIx)].colMeanAbsDevFromHalf) worstColMeanIx = j;
    }

    double worstPairRow = std::numeric_limits<double>::quiet_NaN();
    double worstPairDev = std::numeric_limits<double>::quiet_NaN();
    if (deep) {
        int worstPairIx = 0;
        for (int i = 1; i < maxBits; ++i) {
            double a = rowStats[size_t(i)].pairMaxAbsDev;
            double b = rowStats[size_t(worstPairIx)].pairMaxAbsDev;
            if ((std::isnan(b) && !std::isnan(a)) || (!std::isnan(a) && a > b)) worstPairIx = i;
        }
        worstPairRow = double(rowStats[size_t(worstPairIx)].inputBit);
        worstPairDev = rowStats[size_t(worstPairIx)].pairMaxAbsDev;
    }

    Summary summary;
    summary.tag = tag;
    summary.samples = sampleCount;
    summary.inputBits = maxBits;
    summary.overallMeanFlipRate = meanOf(valid);
    summary.overallStdFlipRate = stdOf(valid, summary.overallMeanFlipRate);
    summary.overallMeanAbsDevFromHalf = meanOf(validDev);
    {
        double rms = 0.0;
        for (double x : valid) {
            double z = x - 0.5;
            rms += z * z;
        }
        summary.overallRmsDevFromHalf = std::sqrt(rms / double(valid.size()));
    }
    summary.overallMaxAbsDevFromHalf = *std::max_element(validDev.begin(), validDev.end());
    summary.overallMeanEntropy = meanOf(validEntropy);
    summary.overallMinCellEntropy = *std::min_element(validEntropy.begin(), validEntropy.end());
    summary.worstCellInputBit = worstInBit;
    summary.worstCellOutputBit = worstOutBit;
    summary.worstCellRate = worstRate;
    summary.worstCellAbsDevFromHalf = std::abs(worstRate - 0.5);
    summary.worstRowInputBit = rowStats[size_t(worstRowMaxIx)].inputBit;
    summary.worstRowMeanAbsDevFromHalf = rowStats[size_t(worstRowMeanIx)].meanAbsDevFromHalf;
    summary.worstRowMaxAbsDevFromHalf = rowStats[size_t(worstRowMaxIx)].maxAbsDevFromHalf;
    summary.worstPairRowInputBit = worstPairRow;
    summary.worstPairRowMaxAbsIndepDev = worstPairDev;
    summary.worstColOutputBit = colStats[size_t(worstColMaxIx)].outputBit;
    summary.worstColMeanAbsDevFromHalf = colStats[size_t(worstColMeanIx)].colMeanAbsDevFromHalf;
    summary.worstColMaxAbsDevFromHalf = colStats[size_t(worstColMaxIx)].colMaxAbsDevFromHalf;

    std::vector<TopCell> top = topCells(infMat, topCount);

    if (!outDir.empty()) {
        fs::create_directories(outDir);

        std::vector<std::string> infHead{"inputBit"};
        for (int j = 0; j < 256; ++j) infHead.push_back("out" + std::to_string(j));
        std::vector<std::vector<std::string>> infRows;
        infRows.reserve(size_t(maxBits));
        for (int i = 0; i < maxBits; ++i) {
            std::vector<std::string> row;
            row.reserve(257);
            row.push_back(std::to_string(i));
            for (int j = 0; j < 256; ++j) row.push_back(cleanCell(infMat[size_t(i)][size_t(j)]));
            infRows.push_back(std::move(row));
        }
        writeTsv((fs::path(outDir) / (tag + ".influence.tsv")).string(), infHead, infRows);

        std::vector<std::vector<std::string>> rowRows;
        for (const auto& r : rowStats) rowRows.push_back({
            std::to_string(r.inputBit), std::to_string(r.samples), cleanCell(r.rowMean), cleanCell(r.rowStd), cleanCell(r.meanAbsDevFromHalf), cleanCell(r.rmsDevFromHalf), cleanCell(r.maxAbsDevFromHalf), cleanCell(r.rowMin), cleanCell(r.rowMax), cleanCell(r.rowMeanEntropy), cleanCell(r.rowMinEntropy), cleanCell(r.pairMeanAbsDev), cleanCell(r.pairRmsAbsDev), cleanCell(r.pairMaxAbsDev)
        });
        writeTsv((fs::path(outDir) / (tag + ".rowStats.tsv")).string(), {"inputBit", "samples", "rowMean", "rowStd", "meanAbsDevFromHalf", "rmsDevFromHalf", "maxAbsDevFromHalf", "rowMin", "rowMax", "rowMeanEntropy", "rowMinEntropy", "pairMeanAbsDev", "pairRmsAbsDev", "pairMaxAbsDev"}, rowRows);

        std::vector<std::vector<std::string>> colRows;
        for (const auto& c : colStats) colRows.push_back({
            std::to_string(c.outputBit), std::to_string(c.rows), cleanCell(c.colMean), cleanCell(c.colStd), cleanCell(c.colMeanAbsDevFromHalf), cleanCell(c.colRmsDevFromHalf), cleanCell(c.colMaxAbsDevFromHalf), cleanCell(c.colMin), cleanCell(c.colMax), cleanCell(c.colMeanEntropy), cleanCell(c.colMinEntropy)
        });
        writeTsv((fs::path(outDir) / (tag + ".colStats.tsv")).string(), {"outputBit", "rows", "colMean", "colStd", "colMeanAbsDevFromHalf", "colRmsDevFromHalf", "colMaxAbsDevFromHalf", "colMin", "colMax", "colMeanEntropy", "colMinEntropy"}, colRows);

        std::vector<std::vector<std::string>> sumRows = {
            {"tag", summary.tag},
            {"samples", std::to_string(summary.samples)},
            {"inputBits", std::to_string(summary.inputBits)},
            {"overallMeanFlipRate", cleanCell(summary.overallMeanFlipRate)},
            {"overallStdFlipRate", cleanCell(summary.overallStdFlipRate)},
            {"overallMeanAbsDevFromHalf", cleanCell(summary.overallMeanAbsDevFromHalf)},
            {"overallRmsDevFromHalf", cleanCell(summary.overallRmsDevFromHalf)},
            {"overallMaxAbsDevFromHalf", cleanCell(summary.overallMaxAbsDevFromHalf)},
            {"overallMeanEntropy", cleanCell(summary.overallMeanEntropy)},
            {"overallMinCellEntropy", cleanCell(summary.overallMinCellEntropy)},
            {"worstCellInputBit", std::to_string(summary.worstCellInputBit)},
            {"worstCellOutputBit", std::to_string(summary.worstCellOutputBit)},
            {"worstCellRate", cleanCell(summary.worstCellRate)},
            {"worstCellAbsDevFromHalf", cleanCell(summary.worstCellAbsDevFromHalf)},
            {"worstRowInputBit", std::to_string(summary.worstRowInputBit)},
            {"worstRowMeanAbsDevFromHalf", cleanCell(summary.worstRowMeanAbsDevFromHalf)},
            {"worstRowMaxAbsDevFromHalf", cleanCell(summary.worstRowMaxAbsDevFromHalf)},
            {"worstPairRowInputBit", cleanCell(summary.worstPairRowInputBit)},
            {"worstPairRowMaxAbsIndepDev", cleanCell(summary.worstPairRowMaxAbsIndepDev)},
            {"worstColOutputBit", std::to_string(summary.worstColOutputBit)},
            {"worstColMeanAbsDevFromHalf", cleanCell(summary.worstColMeanAbsDevFromHalf)},
            {"worstColMaxAbsDevFromHalf", cleanCell(summary.worstColMaxAbsDevFromHalf)}
        };
        writeTsv((fs::path(outDir) / (tag + ".summary.tsv")).string(), {"metric", "value"}, sumRows);

        std::vector<std::vector<std::string>> topRows;
        for (const auto& t : top) topRows.push_back({std::to_string(t.rank), std::to_string(t.inputBit), std::to_string(t.outputBit), cleanCell(t.flipRate), cleanCell(t.absDevFromHalf)});
        writeTsv((fs::path(outDir) / (tag + ".topCells.tsv")).string(), {"rank", "inputBit", "outputBit", "flipRate", "absDevFromHalf"}, topRows);

        if (deep) {
            std::vector<std::vector<std::string>> pairRows;
            pairRows.reserve(size_t(maxBits));
            for (int i = 0; i < maxBits; ++i) {
                std::vector<std::string> row;
                row.reserve(257);
                row.push_back(std::to_string(i));
                for (int j = 0; j < 256; ++j) row.push_back(cleanCell(pairMeanMat[size_t(i)][size_t(j)]));
                pairRows.push_back(std::move(row));
            }
            writeTsv((fs::path(outDir) / (tag + ".pairMean.tsv")).string(), infHead, pairRows);
        }
    }

    return {summary, infMat, pairMeanMat, rowStats, colStats, top};
}

} // namespace

std::vector<BigInt> makeRange(const BigInt& start, uint64_t count) {
    std::vector<BigInt> out;
    out.reserve(size_t(count));
    for (uint64_t i = 0; i < count; ++i) out.push_back(start + BigInt(i));
    return out;
}

HashBytes32 sha256Bytes(const BigInt& x) {
    std::string s = bigToString(x);
    HashBytes32 out{};
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), out.data());
    return out;
}

RunResult runHashAudit(const HashBytesFn& hashFn, const std::vector<BigInt>& samples, int maxBits, const std::string& outDir, const std::string& tag, bool deep, bool showProgress, size_t topCount) {
    uint64_t total = uint64_t(samples.size()) * uint64_t((maxBits > 0 ? maxBits : inferBits(samples)) + 1);
    ProgressBar bar(total, showProgress);
    auto out = runHashAuditInternal(hashFn, samples, maxBits, outDir, tag, deep, &bar, topCount);
    bar.done("done");
    return out;
}

BothResult runDualAudit(const HashBytesFn& shepFn, const Options& opts, bool includeSha256) {
    std::vector<BigInt> samples = resolveSamples(opts);
    if (samples.empty()) throw std::runtime_error("no samples provided");
    int maxBits = opts.maxBits > 0 ? opts.maxBits : inferBits(samples);
    uint64_t total = uint64_t(samples.size()) * uint64_t(maxBits + 1) * uint64_t(includeSha256 ? 2 : 1);
    ProgressBar bar(total, opts.showProgress);
    BothResult out;
    out.shep32 = runHashAuditInternal(shepFn, samples, maxBits, opts.outDir, "shep32", opts.deep, &bar, opts.topCount);
    if (includeSha256) out.sha256 = runHashAuditInternal(sha256Bytes, samples, maxBits, opts.outDir, "sha256", opts.deep, &bar, opts.topCount);
    bar.done("done");
    return out;
}

std::vector<CompareRow> sideBySide(const BothResult& res, int digits, bool fixed) {
    struct Meta { std::string kind; double optimal; double midCase; double worstCase; };
    const Summary& a = res.shep32.summary;
    const Summary& b = res.sha256.summary;
    const std::vector<std::string> metricOrder = {
        "samples", "inputBits", "overallMeanFlipRate", "overallStdFlipRate", "overallMeanAbsDevFromHalf", "overallRmsDevFromHalf", "overallMaxAbsDevFromHalf", "overallMeanEntropy", "overallMinCellEntropy", "worstCellInputBit", "worstCellOutputBit", "worstCellRate", "worstCellAbsDevFromHalf", "worstRowInputBit", "worstRowMeanAbsDevFromHalf", "worstRowMaxAbsDevFromHalf", "worstPairRowInputBit", "worstPairRowMaxAbsIndepDev", "worstColOutputBit", "worstColMeanAbsDevFromHalf", "worstColMaxAbsDevFromHalf"
    };
    const std::unordered_map<std::string, Meta> meta = {
        {"samples", {"info", std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN()}},
        {"inputBits", {"info", std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN()}},
        {"overallMeanFlipRate", {"target", 0.5, 0.5, 0.5}},
        {"overallStdFlipRate", {"min", 0.0, 0.0, 0.5}},
        {"overallMeanAbsDevFromHalf", {"min", 0.0, 0.0, 0.5}},
        {"overallRmsDevFromHalf", {"min", 0.0, 0.0, 0.5}},
        {"overallMaxAbsDevFromHalf", {"min", 0.0, 0.0, 0.5}},
        {"overallMeanEntropy", {"max", 1.0, 1.0, 0.0}},
        {"overallMinCellEntropy", {"max", 1.0, 1.0, 0.0}},
        {"worstCellInputBit", {"loc", std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN()}},
        {"worstCellOutputBit", {"loc", std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN()}},
        {"worstCellRate", {"target", 0.5, 0.5, 0.5}},
        {"worstCellAbsDevFromHalf", {"min", 0.0, 0.0, 0.5}},
        {"worstRowInputBit", {"loc", std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN()}},
        {"worstRowMeanAbsDevFromHalf", {"min", 0.0, 0.0, 0.5}},
        {"worstRowMaxAbsDevFromHalf", {"min", 0.0, 0.0, 0.5}},
        {"worstPairRowInputBit", {"loc", std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN()}},
        {"worstPairRowMaxAbsIndepDev", {"min", 0.0, 0.0, 0.25}},
        {"worstColOutputBit", {"loc", std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN()}},
        {"worstColMeanAbsDevFromHalf", {"min", 0.0, 0.0, 0.5}},
        {"worstColMaxAbsDevFromHalf", {"min", 0.0, 0.0, 0.5}}
    };

    auto get = [](const Summary& s, const std::string& metric) -> double {
        if (metric == "samples") return double(s.samples);
        if (metric == "inputBits") return double(s.inputBits);
        if (metric == "overallMeanFlipRate") return s.overallMeanFlipRate;
        if (metric == "overallStdFlipRate") return s.overallStdFlipRate;
        if (metric == "overallMeanAbsDevFromHalf") return s.overallMeanAbsDevFromHalf;
        if (metric == "overallRmsDevFromHalf") return s.overallRmsDevFromHalf;
        if (metric == "overallMaxAbsDevFromHalf") return s.overallMaxAbsDevFromHalf;
        if (metric == "overallMeanEntropy") return s.overallMeanEntropy;
        if (metric == "overallMinCellEntropy") return s.overallMinCellEntropy;
        if (metric == "worstCellInputBit") return double(s.worstCellInputBit);
        if (metric == "worstCellOutputBit") return double(s.worstCellOutputBit);
        if (metric == "worstCellRate") return s.worstCellRate;
        if (metric == "worstCellAbsDevFromHalf") return s.worstCellAbsDevFromHalf;
        if (metric == "worstRowInputBit") return double(s.worstRowInputBit);
        if (metric == "worstRowMeanAbsDevFromHalf") return s.worstRowMeanAbsDevFromHalf;
        if (metric == "worstRowMaxAbsDevFromHalf") return s.worstRowMaxAbsDevFromHalf;
        if (metric == "worstPairRowInputBit") return s.worstPairRowInputBit;
        if (metric == "worstPairRowMaxAbsIndepDev") return s.worstPairRowMaxAbsIndepDev;
        if (metric == "worstColOutputBit") return double(s.worstColOutputBit);
        if (metric == "worstColMeanAbsDevFromHalf") return s.worstColMeanAbsDevFromHalf;
        if (metric == "worstColMaxAbsDevFromHalf") return s.worstColMaxAbsDevFromHalf;
        return std::numeric_limits<double>::quiet_NaN();
    };

    auto showWorst = [&](const std::string& kind, double midCase, double worstCase) -> std::string {
        if (isMiss(midCase) || isMiss(worstCase)) return "";
        if (kind == "target") return fmtNum(midCase, digits, fixed) + " \u00b1 " + fmtNum(worstCase, digits, fixed);
        return fmtAny(worstCase, digits, fixed);
    };

    auto delta = [](const std::string& kind, double val, double optimal) -> double {
        if (isMiss(val) || isMiss(optimal)) return std::numeric_limits<double>::quiet_NaN();
        if (kind == "target") return std::abs(val - optimal);
        if (kind == "min") return val - optimal;
        if (kind == "max") return optimal - val;
        return std::numeric_limits<double>::quiet_NaN();
    };

    auto better = [](const std::string& kind, double ad, double bd) -> std::string {
        if (kind == "info") return "tie";
        if (kind == "loc") return "\u2014";
        if (isMiss(ad) && isMiss(bd)) return "\u2014";
        if (isMiss(ad)) return "sha256";
        if (isMiss(bd)) return "shep32";
        if (ad < bd) return "shep32";
        if (bd < ad) return "sha256";
        return "tie";
    };

    auto advantage = [](const std::string& kind, double ad, double bd) -> double {
        if (kind == "info" || kind == "loc" || isMiss(ad) || isMiss(bd)) return std::numeric_limits<double>::quiet_NaN();
        return std::abs(ad - bd);
    };

    std::vector<CompareRow> rows;
    rows.reserve(metricOrder.size());
    for (const auto& metric : metricOrder) {
        const auto& m = meta.at(metric);
        double av = get(a, metric), bv = get(b, metric);
        double ad = delta(m.kind, av, m.optimal), bd = delta(m.kind, bv, m.optimal);
        rows.push_back({metric, m.kind, showWorst(m.kind, m.midCase, m.worstCase), fmtAny(m.midCase, digits, fixed), fmtAny(ad, digits, fixed), fmtAny(av, digits, fixed), fmtAny(m.optimal, digits, fixed), fmtAny(bv, digits, fixed), fmtAny(bd, digits, fixed), better(m.kind, ad, bd), fmtAny(advantage(m.kind, ad, bd), digits, fixed)});
    }
    return rows;
}

std::string formatCompareTable(const std::vector<CompareRow>& rows) {
    std::vector<std::string> header = {"metric", "kind", "worstCase", "midCase", "shepDelta", "shep32", "optimal", "sha256", "shaDelta", "better", "advantage"};
    std::array<size_t, 11> widths{};
    for (size_t i = 0; i < header.size(); ++i) widths[i] = header[i].size();
    for (const auto& r : rows) {
        widths[0] = std::max(widths[0], r.metric.size());
        widths[1] = std::max(widths[1], r.kind.size());
        widths[2] = std::max(widths[2], r.worstCase.size());
        widths[3] = std::max(widths[3], r.midCase.size());
        widths[4] = std::max(widths[4], r.shepDelta.size());
        widths[5] = std::max(widths[5], r.shep32.size());
        widths[6] = std::max(widths[6], r.optimal.size());
        widths[7] = std::max(widths[7], r.sha256.size());
        widths[8] = std::max(widths[8], r.shaDelta.size());
        widths[9] = std::max(widths[9], r.better.size());
        widths[10] = std::max(widths[10], r.advantage.size());
    }
    auto appendRow = [&](std::ostringstream& ss, const std::array<std::string, 11>& vals) {
        for (size_t i = 0; i < vals.size(); ++i) {
            if (i) ss << ' ';
            ss << std::left << std::setw(int(widths[i])) << vals[i];
        }
        ss << '\n';
    };
    std::ostringstream ss;
    appendRow(ss, {header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7], header[8], header[9], header[10]});
    for (const auto& r : rows) appendRow(ss, {r.metric, r.kind, r.worstCase, r.midCase, r.shepDelta, r.shep32, r.optimal, r.sha256, r.shaDelta, r.better, r.advantage});
    return ss.str();
}

} // namespace shepAudit
