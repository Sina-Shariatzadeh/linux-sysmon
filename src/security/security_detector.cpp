#include "security/security_detector.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>

#include "core/json.hpp"

namespace sysmon {
namespace {

std::string fmt(const char* f, double v) {
    char buf[64];
    std::snprintf(buf, sizeof buf, f, v);
    return buf;
}

std::string human_rate(double bps) {
    if (bps >= 1e9) return fmt("%.1f GB/s", bps / 1e9);
    if (bps >= 1e6) return fmt("%.1f MB/s", bps / 1e6);
    if (bps >= 1e3) return fmt("%.1f KB/s", bps / 1e3);
    return fmt("%.0f B/s", bps);
}

constexpr std::string_view kDeleted = " (deleted)";

bool ends_with(const std::string& s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string exe_basename(std::string exe) {
    if (ends_with(exe, kDeleted)) exe.resize(exe.size() - kDeleted.size());
    return std::filesystem::path(exe).filename().string();
}

std::string process_details(const ProcessInfo& p) {
    using json::escape;
    return "{\"pid\":" + std::to_string(p.pid) + ",\"ppid\":" + std::to_string(p.ppid) +
           ",\"name\":" + escape(p.name) + ",\"user\":" + escape(p.user) + ",\"exe\":" + escape(p.exe) +
           ",\"cmdline\":" + escape(p.cmdline) + ",\"cpu_pct\":" + json::number(p.cpu_pct) + "}";
}

}  // namespace

SecurityDetector::SecurityDetector(const Config& cfg) : cfg_(cfg) {}

SecurityEvent SecurityDetector::make(TimePoint ts, Severity sev, std::string category, std::string message,
                                     std::string details) const {
    SecurityEvent e;
    e.ts = ts;
    e.severity = sev;
    e.category = std::move(category);
    e.source = "detector";
    e.message = std::move(message);
    e.details_json = std::move(details);
    return e;
}

bool SecurityDetector::cooldown_ok(const std::string& key, TimePoint now) {
    auto it = last_emitted_.find(key);
    if (it != last_emitted_.end() && now - it->second < std::chrono::seconds(cfg_.event_cooldown_s)) return false;
    last_emitted_[key] = now;
    return true;
}

std::vector<SecurityEvent> SecurityDetector::analyze(const MetricsFrame& frame) {
    std::vector<SecurityEvent> out;
    check_cpu(frame, out);
    check_network(frame, out);
    check_processes(frame, out);
    return out;
}

// ---------------------------------------------------------------- CPU ------
void SecurityDetector::check_cpu(const MetricsFrame& f, std::vector<SecurityEvent>& out) {
    const double x = f.cpu.total_pct;
    const double z = cpu_stats_.zscore(x);
    if (cpu_stats_.count() >= cfg_.anomaly_warmup_samples && x >= cfg_.cpu_anomaly_min_pct &&
        z >= cfg_.anomaly_zscore && cooldown_ok("cpu_anomaly", f.ts)) {
        const std::string top = f.processes.processes.empty() ? "" : f.processes.processes.front().name;
        auto e = make(f.ts, x >= 95 ? Severity::Critical : Severity::Warning, "cpu_anomaly",
                      "Unusual CPU usage " + fmt("%.1f%%", x) + " (baseline " + fmt("%.1f%%", cpu_stats_.mean()) +
                          ", z=" + fmt("%.1f", z) + ")" + (top.empty() ? "" : ", top process: " + top),
                      "{\"value\":" + json::number(x) + ",\"baseline\":" + json::number(cpu_stats_.mean()) +
                          ",\"zscore\":" + json::number(z) + ",\"top_process\":" + json::escape(top) + "}");
        e.source = "cpu";
        out.push_back(std::move(e));
    }
    cpu_stats_.update(x);
}

// ------------------------------------------------------------ Network ------
void SecurityDetector::check_network(const MetricsFrame& f, std::vector<SecurityEvent>& out) {
    const auto& n = f.network;
    const bool warm = rx_stats_.count() >= cfg_.anomaly_warmup_samples;

    auto check_rate = [&](RollingStats& stats, double value, const char* dir) {
        const double z = stats.zscore(value);
        if (warm && value >= cfg_.net_anomaly_min_bps && z >= cfg_.anomaly_zscore &&
            cooldown_ok(std::string("net_") + dir, f.ts)) {
            auto e = make(f.ts, Severity::Warning, "network_anomaly",
                          std::string("Unusual network ") + dir + " traffic " + human_rate(value) + " (baseline " +
                              human_rate(stats.mean()) + ", z=" + fmt("%.1f", z) + ")",
                          std::string("{\"direction\":\"") + dir + "\",\"bps\":" + json::number(value) +
                              ",\"baseline\":" + json::number(stats.mean()) + ",\"zscore\":" + json::number(z) + "}");
            e.source = "network";
            out.push_back(std::move(e));
        }
        stats.update(value);
    };
    check_rate(rx_stats_, n.total_rx_bps, "rx");
    check_rate(tx_stats_, n.total_tx_bps, "tx");

    const double conns = n.tcp_established;
    const double zc = tcp_stats_.zscore(conns);
    if (warm && conns >= cfg_.tcp_anomaly_min_connections && zc >= cfg_.anomaly_zscore &&
        cooldown_ok("tcp_conn", f.ts)) {
        auto e = make(f.ts, Severity::Warning, "network_anomaly",
                      "Spike in established TCP connections: " + std::to_string(n.tcp_established) + " (baseline " +
                          fmt("%.0f", tcp_stats_.mean()) + ")",
                      "{\"established\":" + std::to_string(n.tcp_established) +
                          ",\"baseline\":" + json::number(tcp_stats_.mean()) + "}");
        e.source = "network";
        out.push_back(std::move(e));
    }
    tcp_stats_.update(conns);

    // New listening ports (after the first frame establishes the baseline).
    if (!ports_baselined_) {
        known_ports_.insert(n.listen_ports.begin(), n.listen_ports.end());
        ports_baselined_ = true;
        return;
    }
    for (uint16_t port : n.listen_ports) {
        if (!known_ports_.insert(port).second) continue;
        auto e = make(f.ts, Severity::Warning, "new_listening_port",
                      "New TCP port listening: " + std::to_string(port), "{\"port\":" + std::to_string(port) + "}");
        e.source = "network";
        out.push_back(std::move(e));
    }
}

// ---------------------------------------------------------- Processes ------
void SecurityDetector::check_processes(const MetricsFrame& f, std::vector<SecurityEvent>& out) {
    std::set<ProcKey> alive;
    for (const auto& p : f.processes.processes) {
        const ProcKey key{p.pid, p.start_ticks};
        alive.insert(key);

        if (!reported_procs_.count(key)) {
            const std::string base = p.exe.empty() ? p.name : exe_basename(p.exe);
            std::vector<std::string> reasons;
            Severity sev = Severity::Warning;

            const auto& names = cfg_.suspicious_names;
            if (std::find(names.begin(), names.end(), p.name) != names.end() ||
                std::find(names.begin(), names.end(), base) != names.end()) {
                reasons.push_back("known suspicious tool/miner name '" + base + "'");
                sev = Severity::Critical;
            }
            for (const auto& dir : cfg_.suspicious_paths) {
                if (!p.exe.empty() && p.exe.rfind(dir, 0) == 0) {
                    reasons.push_back("executing from world-writable directory " + dir);
                    sev = Severity::Critical;
                    break;
                }
            }
            if (ends_with(p.exe, kDeleted)) reasons.push_back("binary was deleted from disk while running");

            if (!reasons.empty()) {
                std::string msg = "Suspicious process " + p.name + " (pid " + std::to_string(p.pid) + ", user " +
                                  p.user + "): ";
                for (std::size_t i = 0; i < reasons.size(); ++i) msg += (i ? "; " : "") + reasons[i];
                auto e = make(f.ts, sev, "suspicious_process", msg, process_details(p));
                e.source = "process";
                e.pid = p.pid;
                out.push_back(std::move(e));
                reported_procs_.insert(key);
            }
        }

        if (p.cpu_pct >= cfg_.proc_cpu_hog_pct) {
            if (++hog_counter_[key] == cfg_.proc_cpu_hog_samples) {
                auto e = make(f.ts, Severity::Warning, "process_cpu_hog",
                              "Process " + p.name + " (pid " + std::to_string(p.pid) + ") has used " +
                                  fmt("%.0f%%", p.cpu_pct) + " CPU for " + std::to_string(cfg_.proc_cpu_hog_samples) +
                                  " consecutive samples",
                              process_details(p));
                e.source = "process";
                e.pid = p.pid;
                out.push_back(std::move(e));
            }
        } else {
            hog_counter_.erase(key);
        }
    }

    // Forget processes that have exited.
    std::erase_if(reported_procs_, [&](const ProcKey& k) { return !alive.count(k); });
    std::erase_if(hog_counter_, [&](const auto& kv) { return !alive.count(kv.first); });
}

// --------------------------------------------------------------- Auth ------
std::vector<SecurityEvent> SecurityDetector::on_auth_failure(const parsers::AuthFailure& a, TimePoint ts) {
    std::vector<SecurityEvent> out;
    const std::string origin = a.ip.empty() ? "local" : a.ip;
    const std::string key = a.ip.empty() ? "local:" + a.user : a.ip;
    const std::string details = "{\"service\":" + json::escape(a.service) + ",\"user\":" + json::escape(a.user) +
                                ",\"ip\":" + json::escape(a.ip) +
                                ",\"invalid_user\":" + (a.invalid_user ? "true" : "false") + "}";

    auto e = make(ts, Severity::Info, "failed_login",
                  "Failed " + a.service + " login for " + (a.invalid_user ? "invalid user " : "user ") +
                      (a.user.empty() ? "?" : a.user) + " from " + origin,
                  details);
    e.source = "auth";
    out.push_back(std::move(e));

    auto& window = auth_failures_[key];
    window.push_back(ts);
    const auto cutoff = ts - std::chrono::seconds(cfg_.failed_login_window_s);
    while (!window.empty() && window.front() < cutoff) window.pop_front();

    if (static_cast<int>(window.size()) >= cfg_.failed_login_threshold && cooldown_ok("brute:" + key, ts)) {
        auto b = make(ts, Severity::Critical, "brute_force",
                      "Possible brute-force attack: " + std::to_string(window.size()) + " failed logins from " +
                          origin + " in the last " + std::to_string(cfg_.failed_login_window_s) + "s",
                      "{\"origin\":" + json::escape(origin) + ",\"failures\":" + std::to_string(window.size()) +
                          ",\"window_s\":" + std::to_string(cfg_.failed_login_window_s) + "}");
        b.source = "auth";
        out.push_back(std::move(b));
    }
    return out;
}

}  // namespace sysmon
