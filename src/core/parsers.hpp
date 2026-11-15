#pragma once
// Pure parsing functions for the text formats exposed by /proc.
// They take the file *contents* (not paths) so they can be unit tested
// with canned input and reused by every collector.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "core/types.hpp"

namespace sysmon::parsers {

/// Reads a whole file; returns std::nullopt when it cannot be opened
/// (processes vanish between readdir() and open() all the time).
std::optional<std::string> read_file(const std::filesystem::path& path);

// ---- /proc/stat --------------------------------------------------------
struct ProcStat {
    CpuTimes total;
    std::vector<CpuTimes> cores;
    uint64_t ctxt = 0;
    uint64_t btime = 0;  ///< boot time, epoch seconds
    int procs_running = 0;
};
ProcStat parse_proc_stat(std::string_view text);

/// Usage percentages between two samples of the same CPU line.
CoreUsage compute_core_usage(const CpuTimes& prev, const CpuTimes& cur, int core);

// ---- /proc/loadavg, /proc/uptime ---------------------------------------
struct LoadAvg {
    double l1 = 0, l5 = 0, l15 = 0;
};
LoadAvg parse_loadavg(std::string_view text);
double parse_uptime(std::string_view text);

// ---- /proc/meminfo -----------------------------------------------------
MemorySnapshot parse_meminfo(std::string_view text);

// ---- /proc/diskstats ---------------------------------------------------
std::vector<DiskCounters> parse_diskstats(std::string_view text);

// ---- /proc/net/dev -----------------------------------------------------
std::vector<NetCounters> parse_net_dev(std::string_view text);

// ---- /proc/net/tcp, /proc/net/tcp6 -------------------------------------
struct TcpSummary {
    int established = 0, listen = 0, time_wait = 0, total = 0;
    std::set<uint16_t> listen_ports;
};
void accumulate_proc_net_tcp(std::string_view text, TcpSummary& out);

// ---- /proc/<pid>/stat, /proc/<pid>/status ------------------------------
struct PidStat {
    int pid = 0;
    std::string comm;
    char state = '?';
    int ppid = 0;
    uint64_t utime = 0, stime = 0;  ///< clock ticks
    int num_threads = 0;
    uint64_t starttime = 0;         ///< clock ticks since boot
    uint64_t vsize = 0;             ///< bytes
    int64_t rss_pages = 0;
};
std::optional<PidStat> parse_pid_stat(std::string_view text);
std::optional<uint32_t> parse_status_uid(std::string_view text);

/// /proc/<pid>/cmdline uses NUL separators; turn them into spaces.
std::string normalize_cmdline(std::string raw, std::size_t max_len = 512);

// ---- /proc/mounts ------------------------------------------------------
struct MountEntry {
    std::string device, mount_point, fs_type;
};
std::vector<MountEntry> parse_mounts(std::string_view text);

// ---- auth.log / secure -------------------------------------------------
struct AuthFailure {
    std::string service;   ///< "sshd", "sudo", "su", "login", ...
    std::string user;
    std::string ip;        ///< empty for local failures
    bool invalid_user = false;
};
/// Recognises failed authentication lines from sshd and PAM.
std::optional<AuthFailure> parse_auth_failure(std::string_view line);

}  // namespace sysmon::parsers
