#pragma once

#include <algorithm>
#include <cmath>

namespace sysmon {

/// Exponentially weighted mean / variance used as a cheap, adaptive
/// baseline for anomaly detection (z-score of a new sample against the
/// recent history). `min_stddev` prevents a perfectly flat baseline from
/// turning tiny fluctuations into huge z-scores.
class RollingStats {
public:
    explicit RollingStats(double alpha = 0.05, double min_stddev = 1.0) : alpha_(alpha), min_stddev_(min_stddev) {}

    /// z-score of `x` against the baseline *before* it is incorporated.
    double zscore(double x) const {
        if (count_ == 0) return 0.0;
        return (x - mean_) / stddev();
    }

    void update(double x) {
        if (count_ == 0) {
            mean_ = x;
            var_ = 0.0;
        } else {
            const double diff = x - mean_;
            const double incr = alpha_ * diff;
            mean_ += incr;
            var_ = (1.0 - alpha_) * (var_ + diff * incr);
        }
        ++count_;
    }

    double mean() const { return mean_; }
    double stddev() const { return std::max(std::sqrt(var_), min_stddev_); }
    long count() const { return count_; }

private:
    double alpha_;
    double min_stddev_;
    double mean_ = 0.0;
    double var_ = 0.0;
    long count_ = 0;
};

}  // namespace sysmon
