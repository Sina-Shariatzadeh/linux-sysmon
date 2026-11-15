#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "core/config.hpp"
#include "core/types.hpp"

namespace sysmon {

/// Threshold alerting with hysteresis: a metric must stay above its
/// threshold for `alert_sustain_samples` consecutive frames before an alert
/// fires, fires at most once per `alert_cooldown_s`, and emits a "resolved"
/// alert when it drops back below.
class AlertManager {
public:
    explicit AlertManager(const Config& cfg);
    std::vector<Alert> evaluate(const MetricsFrame& frame);

private:
    struct RuleState {
        int over = 0;
        bool active = false;
        bool fired_once = false;
        TimePoint last_fired{};
    };
    void check(const std::string& metric, const std::string& label, double value, double threshold, TimePoint ts,
               std::vector<Alert>& out);

    Config cfg_;
    std::unordered_map<std::string, RuleState> state_;
};

}  // namespace sysmon
