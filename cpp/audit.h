#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

namespace shepAudit {

using BigInt = boost::multiprecision::cpp_int;
using HashBytes32 = std::array<uint8_t, 32>;
using HashBytesFn = std::function<HashBytes32(const BigInt&)>;

struct RowStat {
    int inputBit = 0;
    int samples = 0;
    double rowMean = 0.0;
    double rowStd = 0.0;
    double meanAbsDevFromHalf = 0.0;
    double rmsDevFromHalf = 0.0;
    double maxAbsDevFromHalf = 0.0;
    double rowMin = 0.0;
    double rowMax = 0.0;
    double rowMeanEntropy = 0.0;
    double rowMinEntropy = 0.0;
    double pairMeanAbsDev = 0.0;
    double pairRmsAbsDev = 0.0;
    double pairMaxAbsDev = 0.0;
};

struct ColStat {
    int outputBit = 0;
    int rows = 0;
    double colMean = 0.0;
    double colStd = 0.0;
    double colMeanAbsDevFromHalf = 0.0;
    double colRmsDevFromHalf = 0.0;
    double colMaxAbsDevFromHalf = 0.0;
    double colMin = 0.0;
    double colMax = 0.0;
    double colMeanEntropy = 0.0;
    double colMinEntropy = 0.0;
};

struct TopCell {
    int rank = 0;
    int inputBit = 0;
    int outputBit = 0;
    double flipRate = 0.0;
    double absDevFromHalf = 0.0;
};

struct Summary {
    std::string tag;
    int samples = 0;
    int inputBits = 0;
    double overallMeanFlipRate = 0.0;
    double overallStdFlipRate = 0.0;
    double overallMeanAbsDevFromHalf = 0.0;
    double overallRmsDevFromHalf = 0.0;
    double overallMaxAbsDevFromHalf = 0.0;
    double overallMeanEntropy = 0.0;
    double overallMinCellEntropy = 0.0;
    int worstCellInputBit = 0;
    int worstCellOutputBit = 0;
    double worstCellRate = 0.0;
    double worstCellAbsDevFromHalf = 0.0;
    int worstRowInputBit = 0;
    double worstRowMeanAbsDevFromHalf = 0.0;
    double worstRowMaxAbsDevFromHalf = 0.0;
    double worstPairRowInputBit = 0.0;
    double worstPairRowMaxAbsIndepDev = 0.0;
    int worstColOutputBit = 0;
    double worstColMeanAbsDevFromHalf = 0.0;
    double worstColMaxAbsDevFromHalf = 0.0;
};

struct RunResult {
    Summary summary;
    std::vector<std::vector<double>> influence;
    std::vector<std::vector<double>> pairMean;
    std::vector<RowStat> rowStats;
    std::vector<ColStat> colStats;
    std::vector<TopCell> topCells;
};

struct BothResult {
    RunResult shep32;
    RunResult sha256;
};

struct CompareRow {
    std::string metric;
    std::string kind;
    std::string worstCase;
    std::string midCase;
    std::string shepDelta;
    std::string shep32;
    std::string optimal;
    std::string sha256;
    std::string shaDelta;
    std::string better;
    std::string advantage;
};

struct Options {
    std::vector<BigInt> samples;
    BigInt start = 0;
    uint64_t count = 5000;
    int maxBits = -1;
    std::string outDir;
    bool deep = false;
    bool showProgress = true;
    size_t topCount = 32;
};

std::vector<BigInt> makeRange(const BigInt& start, uint64_t count);
HashBytes32 sha256Bytes(const BigInt& x);
RunResult runHashAudit(const HashBytesFn& hashFn, const std::vector<BigInt>& samples, int maxBits, const std::string& outDir, const std::string& tag, bool deep, bool showProgress, size_t topCount);
BothResult runDualAudit(const HashBytesFn& shepFn, const Options& opts, bool includeSha256 = true);
std::vector<CompareRow> sideBySide(const BothResult& res, int digits = 12, bool fixed = true);
std::string formatCompareTable(const std::vector<CompareRow>& rows);

} // namespace shepAudit
