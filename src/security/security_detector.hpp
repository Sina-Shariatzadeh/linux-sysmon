#pragma once

#include <deque>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/config.hpp"
#include "core/parsers.hpp"
#include "core/types.hpp"
#include "security/rolling_stats.hpp"

namespace sysmon {

/// Turns metric frames and authentication failures into security events.
///
/// Detections:
///  * cpu_anomaly        - total CPU far above its adaptive baseline
///  * network_anomaly    - RX/TX throughput or TCP connection spikes
///  * new_listening_port - a TCP port starts listening after the baseline
///  * suspicious_process - known-bad names, binaries in /tmp-like paths,
///                         deleted executables, sustained CPU hogs
///  * failed_login       - every failed authentication
///  * brute_force        - too many failures from one source in a window
///
/// Not thread-safe: the engine calls it from its single control thread.
class SecurityDetector {
public:
    explicit SecurityDetector(const Config& cfg);

    std::vector<SecurityEvent> analyze(const MetricsFrame& frame);
    std::vector<SecurityEvent> on_auth_failure(const parsers::AuthFailure& failure, TimePoint ts);

private:
    void check_cpu(const MetricsFrame& f, std::vector<SecurityEvent>& out);
    void check_network(const MetricsFrame& f, std::vector<SecurityEvent>& out);
    void check_processes(const MetricsFrame& f, std::vector<SecurityEvent>& out);

    bool cooldown_ok(const std::string& key, TimePoint now);
    SecurityEvent make(TimePoint ts, Severity sev, std::string category, std::string message,
                       std::string details = "{}") const;

    Config cfg_;
    RollingStats cpu_stats_{0.05, 5.0};
    RollingStats rx_stats_{0.05, 1e5};
    RollingStats tx_stats_{0.05, 1e5};
    RollingStats tcp_stats_{0.05, 5.0};

    bool ports_baselined_ = false;
    std::set<uint16_t> known_ports_;

    using ProcKey = std::pair<int, uint64_t>;  // pid + start ticks
    std::set<ProcKey> reported_procs_;
    std::map<ProcKey, int> hog_counter_;

    std::unordered_map<std::string, std::deque<TimePoint>> auth_failures_;
    std::unordered_map<std::string, TimePoint> last_emitted_;
};

}  // namespace sysmon
