#include "security/alert_manager.hpp"

#include <cstdio>

namespace sysmon {

AlertManager::AlertManager(const Config& cfg) : cfg_(cfg) {}

std::vector<Alert> AlertManager::evaluate(const MetricsFrame& f) {
    std::vector<Alert> out;
    check("cpu", "CPU usage", f.cpu.total_pct, cfg_.cpu_alert_pct, f.ts, out);
    check("memory", "Memory usage", f.memory.used_pct, cfg_.mem_alert_pct, f.ts, out);
    if (f.memory.swap_total_kb > 0) check("swap", "Swap usage", f.memory.swap_pct, cfg_.swap_alert_pct, f.ts, out);
    for (const auto& fs : f.disk.filesystems)
        check("disk:" + fs.mount_point, "Filesystem " + fs.mount_point, fs.used_pct, cfg_.disk_alert_pct, f.ts, out);
    return out;
}

void AlertManager::check(const std::string& metric, const std::string& label, double value, double threshold,
                         TimePoint ts, std::vector<Alert>& out) {
    auto& st = state_[metric];
    char buf[160];

    if (value >= threshold) {
        ++st.over;
        const bool cooled = !st.fired_once || ts - st.last_fired >= std::chrono::seconds(cfg_.alert_cooldown_s);
        if (!st.active && st.over >= cfg_.alert_sustain_samples && cooled) {
            Alert a;
            a.ts = ts;
            a.metric = metric;
            a.value = value;
            a.threshold = threshold;
            a.severity = value >= threshold + (100.0 - threshold) / 2.0 ? Severity::Critical : Severity::Warning;
            std::snprintf(buf, sizeof buf, "%s is %.1f%% (threshold %.0f%%) for %d samples", label.c_str(), value,
                          threshold, st.over);
            a.message = buf;
            out.push_back(std::move(a));
            st.active = true;
            st.fired_once = true;
            st.last_fired = ts;
        }
        return;
    }

    st.over = 0;
    if (st.active) {
        st.active = false;
        Alert a;
        a.ts = ts;
        a.metric = metric;
        a.value = value;
        a.threshold = threshold;
        a.severity = Severity::Info;
        a.resolved = true;
        std::snprintf(buf, sizeof buf, "%s back to normal: %.1f%%", label.c_str(), value);
        a.message = buf;
        out.push_back(std::move(a));
    }
}

}  // namespace sysmon
