#pragma once
// Plain data types shared by collectors, the engine, the database layer and
// the dashboard. No behaviour lives here.

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sysmon {

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

inline double to_epoch_seconds(TimePoint tp) {
    return std::chrono::duration<double>(tp.time_since_epoch()).count();
}

inline TimePoint from_epoch_seconds(double s) {
    return TimePoint(std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(s)));
}

// ----------------------------------------------------------------- CPU -----
/// Raw jiffy counters from one "cpu" line of /proc/stat.
struct CpuTimes {
    uint64_t user = 0, nice = 0, system = 0, idle = 0;
    uint64_t iowait = 0, irq = 0, softirq = 0, steal = 0;

    uint64_t idle_all() const { return idle + iowait; }
    uint64_t total() const { return user + nice + system + idle + iowait + irq + softirq + steal; }
};

struct CoreUsage {
    int core = -1;            ///< -1 = aggregate of all cores
    double usage_pct = 0;
    double user_pct = 0;
    double system_pct = 0;
    double iowait_pct = 0;
};

struct CpuSnapshot {
    double total_pct = 0;
    std::vector<CoreUsage> cores;
    double load1 = 0, load5 = 0, load15 = 0;
    double uptime_s = 0;
    double ctx_switches_per_s = 0;
};

// -------------------------------------------------------------- Memory -----
struct MemorySnapshot {
    uint64_t total_kb = 0, free_kb = 0, available_kb = 0, used_kb = 0;
    uint64_t buffers_kb = 0, cached_kb = 0;
    uint64_t swap_total_kb = 0, swap_free_kb = 0, swap_used_kb = 0;
    double used_pct = 0;
    double swap_pct = 0;
};

// ---------------------------------------------------------------- Disk -----
/// Raw counters from one line of /proc/diskstats.
struct DiskCounters {
    std::string device;
    uint64_t reads_completed = 0, sectors_read = 0;
    uint64_t writes_completed = 0, sectors_written = 0;
    uint64_t io_ms = 0;  ///< time spent doing I/O (ms)
};

struct DiskIo {
    std::string device;
    double read_bps = 0, write_bps = 0;   ///< bytes / second
    double reads_ps = 0, writes_ps = 0;   ///< operations / second
    double util_pct = 0;
};

struct FilesystemUsage {
    std::string mount_point, device, fs_type;
    uint64_t total_bytes = 0, used_bytes = 0, avail_bytes = 0;
    double used_pct = 0;
};

struct DiskSnapshot {
    std::vector<DiskIo> io;
    std::vector<FilesystemUsage> filesystems;
};

// ------------------------------------------------------------- Network -----
/// Raw counters from one line of /proc/net/dev.
struct NetCounters {
    std::string iface;
    uint64_t rx_bytes = 0, rx_packets = 0, rx_errs = 0, rx_drop = 0;
    uint64_t tx_bytes = 0, tx_packets = 0, tx_errs = 0, tx_drop = 0;
};

struct NetRate {
    std::string iface;
    double rx_bps = 0, tx_bps = 0;   ///< bytes / second
    double rx_pps = 0, tx_pps = 0;   ///< packets / second
    uint64_t rx_errs = 0, tx_errs = 0;
};

struct NetworkSnapshot {
    std::vector<NetRate> interfaces;
    double total_rx_bps = 0, total_tx_bps = 0;
    int tcp_established = 0, tcp_listen = 0, tcp_time_wait = 0, tcp_total = 0;
    std::vector<uint16_t> listen_ports;  ///< sorted, unique
};

// ----------------------------------------------------------- Processes -----
struct ProcessInfo {
    int pid = 0, ppid = 0;
    std::string name;      ///< comm
    std::string cmdline;
    std::string exe;       ///< resolved /proc/<pid>/exe (may be empty without privileges)
    std::string user;
    uint32_t uid = 0;
    char state = '?';
    double cpu_pct = 0;    ///< 100 = one full core (like top)
    uint64_t rss_kb = 0, vsize_kb = 0;
    int threads = 0;
    uint64_t start_ticks = 0;  ///< start time in clock ticks since boot (identity with pid)
    double start_time = 0;     ///< epoch seconds
};

struct ProcessSnapshot {
    std::vector<ProcessInfo> processes;  ///< sorted by cpu_pct descending
    int total = 0, running = 0, threads = 0;
};

// ------------------------------------------------------------ Combined -----
struct MetricsFrame {
    TimePoint ts{};
    std::string hostname;
    uint64_t sequence = 0;
    CpuSnapshot cpu;
    MemorySnapshot memory;
    DiskSnapshot disk;
    NetworkSnapshot network;
    ProcessSnapshot processes;
};

// ------------------------------------------------------ Events / alerts -----
enum class Severity { Info = 0, Warning = 1, Critical = 2 };

inline const char* to_string(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Warning: return "warning";
        case Severity::Critical: return "critical";
    }
    return "info";
}

inline Severity severity_from_string(const std::string& s) {
    if (s == "critical") return Severity::Critical;
    if (s == "warning") return Severity::Warning;
    return Severity::Info;
}

struct SecurityEvent {
    TimePoint ts{};
    Severity severity = Severity::Info;
    std::string category;   ///< e.g. "cpu_anomaly", "suspicious_process", "brute_force"
    std::string source;     ///< collector / subsystem that raised it
    std::string message;
    std::optional<int> pid;
    std::string details_json = "{}";
};

struct Alert {
    TimePoint ts{};
    Severity severity = Severity::Warning;
    std::string metric;     ///< e.g. "cpu", "memory", "disk:/home"
    double value = 0;
    double threshold = 0;
    std::string message;
    bool resolved = false;  ///< true = metric returned below threshold
};

}  // namespace sysmon
