#include "core/config.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace sysmon {
namespace {

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split_list(const std::string& v) {
    std::vector<std::string> out;
    std::stringstream ss(v);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item = trim(item);
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

bool to_bool(const std::string& v) {
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

}  // namespace

Config Config::from_string(const std::string& text) {
    Config c;
    std::istringstream in(text);
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        line = trim(line);
        if (line.empty() || line.front() == '[') continue;  // allow [sections] for readability

        const auto eq = line.find('=');
        if (eq == std::string::npos)
            throw std::runtime_error("config line " + std::to_string(lineno) + ": expected key = value");
        const std::string key = trim(line.substr(0, eq));
        const std::string val = trim(line.substr(eq + 1));

        try {
            if (key == "proc_root") c.proc_root = val;
            else if (key == "sys_root") c.sys_root = val;
            else if (key == "auth_log_paths") c.auth_log_paths = split_list(val);
            else if (key == "include_loopback") c.include_loopback = to_bool(val);
            else if (key == "hostname") c.hostname = val;
            else if (key == "interval_ms") c.interval = std::chrono::milliseconds(std::stoi(val));
            else if (key == "worker_threads") c.worker_threads = std::stoi(val);
            else if (key == "db_enabled") c.db_enabled = to_bool(val);
            else if (key == "db_conninfo") c.db_conninfo = val;
            else if (key == "retention_days") c.retention_days = std::stoi(val);
            else if (key == "process_top_n") c.process_top_n = std::stoi(val);
            else if (key == "process_store_every") c.process_store_every = std::stoi(val);
            else if (key == "db_queue_capacity") c.db_queue_capacity = std::stoi(val);
            else if (key == "live_enabled") c.live_enabled = to_bool(val);
            else if (key == "live_bind") c.live_bind = val;
            else if (key == "live_port") c.live_port = static_cast<uint16_t>(std::stoi(val));
            else if (key == "live_top_n") c.live_top_n = std::stoi(val);
            else if (key == "cpu_alert_pct") c.cpu_alert_pct = std::stod(val);
            else if (key == "mem_alert_pct") c.mem_alert_pct = std::stod(val);
            else if (key == "swap_alert_pct") c.swap_alert_pct = std::stod(val);
            else if (key == "disk_alert_pct") c.disk_alert_pct = std::stod(val);
            else if (key == "alert_sustain_samples") c.alert_sustain_samples = std::stoi(val);
            else if (key == "alert_cooldown_s") c.alert_cooldown_s = std::stoi(val);
            else if (key == "anomaly_zscore") c.anomaly_zscore = std::stod(val);
            else if (key == "anomaly_warmup_samples") c.anomaly_warmup_samples = std::stoi(val);
            else if (key == "cpu_anomaly_min_pct") c.cpu_anomaly_min_pct = std::stod(val);
            else if (key == "net_anomaly_min_bps") c.net_anomaly_min_bps = std::stod(val);
            else if (key == "tcp_anomaly_min_connections") c.tcp_anomaly_min_connections = std::stoi(val);
            else if (key == "proc_cpu_hog_pct") c.proc_cpu_hog_pct = std::stod(val);
            else if (key == "proc_cpu_hog_samples") c.proc_cpu_hog_samples = std::stoi(val);
            else if (key == "failed_login_threshold") c.failed_login_threshold = std::stoi(val);
            else if (key == "failed_login_window_s") c.failed_login_window_s = std::stoi(val);
            else if (key == "event_cooldown_s") c.event_cooldown_s = std::stoi(val);
            else if (key == "suspicious_names") c.suspicious_names = split_list(val);
            else if (key == "suspicious_paths") c.suspicious_paths = split_list(val);
            else throw std::runtime_error("unknown key '" + key + "'");
        } catch (const std::invalid_argument&) {
            throw std::runtime_error("config line " + std::to_string(lineno) + ": invalid value for '" + key + "'");
        } catch (const std::out_of_range&) {
            throw std::runtime_error("config line " + std::to_string(lineno) + ": value out of range for '" + key + "'");
        } catch (const std::runtime_error& e) {
            throw std::runtime_error("config line " + std::to_string(lineno) + ": " + e.what());
        }
    }

    if (c.interval.count() < 100) throw std::runtime_error("interval_ms must be >= 100");
    if (c.worker_threads < 1) c.worker_threads = 1;
    if (c.process_store_every < 1) c.process_store_every = 1;
    return c;
}

Config Config::load(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open config file: " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    return from_string(ss.str());
}

}  // namespace sysmon
