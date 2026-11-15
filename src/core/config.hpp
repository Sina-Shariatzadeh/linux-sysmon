#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace sysmon {

/// Runtime configuration. Loaded from a simple `key = value` file
/// (see config/sysmon.conf); every field has a sensible default.
struct Config {
    // --- sources -------------------------------------------------------
    std::string proc_root = "/proc";
    std::string sys_root = "/sys";
    std::vector<std::string> auth_log_paths{"/var/log/auth.log", "/var/log/secure"};
    bool include_loopback = false;
    std::string hostname;  ///< empty = gethostname()

    // --- engine --------------------------------------------------------
    std::chrono::milliseconds interval{1000};
    int worker_threads = 4;

    // --- database ------------------------------------------------------
    bool db_enabled = true;
    std::string db_conninfo = "host=localhost port=5432 dbname=sysmon user=sysmon password=sysmon";
    int retention_days = 30;
    int process_top_n = 25;         ///< processes stored per process sample
    int process_store_every = 5;    ///< store processes every N frames
    int db_queue_capacity = 600;    ///< frames buffered while DB is unreachable

    // --- live stream (Boost.Asio) --------------------------------------
    bool live_enabled = true;
    std::string live_bind = "127.0.0.1";
    uint16_t live_port = 9090;
    int live_top_n = 50;            ///< processes included in each live frame

    // --- threshold alerts ----------------------------------------------
    double cpu_alert_pct = 90;
    double mem_alert_pct = 90;
    double swap_alert_pct = 50;
    double disk_alert_pct = 90;
    int alert_sustain_samples = 5;
    int alert_cooldown_s = 300;

    // --- security detection --------------------------------------------
    double anomaly_zscore = 3.5;
    int anomaly_warmup_samples = 30;
    double cpu_anomaly_min_pct = 60;        ///< ignore "anomalies" below this
    double net_anomaly_min_bps = 5e6;       ///< ignore network spikes below 5 MB/s
    int tcp_anomaly_min_connections = 100;
    double proc_cpu_hog_pct = 90;
    int proc_cpu_hog_samples = 30;
    int failed_login_threshold = 5;
    int failed_login_window_s = 300;
    int event_cooldown_s = 120;
    std::vector<std::string> suspicious_names{"xmrig", "minerd", "cpuminer", "kdevtmpfsi", "kinsing",
                                              "ncat", "socat", "nc", "hydra", "masscan"};
    std::vector<std::string> suspicious_paths{"/tmp/", "/dev/shm/", "/var/tmp/"};

    static Config from_string(const std::string& text);
    static Config load(const std::string& path);  ///< throws std::runtime_error
};

}  // namespace sysmon
