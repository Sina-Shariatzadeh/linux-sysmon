#include "core/parsers.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <regex>
#include <sstream>

namespace sysmon::parsers {
namespace {

std::vector<std::string_view> split_ws(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        const std::size_t start = i;
        while (i < s.size() && s[i] != ' ' && s[i] != '\t') ++i;
        if (i > start) out.push_back(s.substr(start, i - start));
    }
    return out;
}

template <typename Fn>
void for_each_line(std::string_view text, Fn&& fn) {
    std::size_t pos = 0;
    while (pos < text.size()) {
        auto nl = text.find('\n', pos);
        if (nl == std::string_view::npos) nl = text.size();
        std::string_view line = text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        fn(line);
        pos = nl + 1;
    }
}

template <typename T>
T to_num(std::string_view s, T fallback = 0) {
    T value = fallback;
    const auto res = std::from_chars(s.data(), s.data() + s.size(), value);
    return res.ec == std::errc() ? value : fallback;
}

double to_double(std::string_view s) {
    // std::from_chars for double is not available on every libstdc++ we target.
    try {
        return std::stod(std::string(s));
    } catch (...) {
        return 0.0;
    }
}

double pct(double part, double whole) { return whole > 0 ? 100.0 * part / whole : 0.0; }

uint64_t delta(uint64_t a, uint64_t b) { return b >= a ? b - a : 0; }  // tolerate counter resets

}  // namespace

std::optional<std::string> read_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// ------------------------------------------------------------ /proc/stat ---
ProcStat parse_proc_stat(std::string_view text) {
    ProcStat st;
    for_each_line(text, [&](std::string_view line) {
        const auto f = split_ws(line);
        if (f.empty()) return;
        if (f[0].substr(0, 3) == "cpu") {
            CpuTimes t;
            uint64_t* slots[] = {&t.user, &t.nice, &t.system, &t.idle, &t.iowait, &t.irq, &t.softirq, &t.steal};
            for (std::size_t i = 0; i < 8 && i + 1 < f.size(); ++i) *slots[i] = to_num<uint64_t>(f[i + 1]);
            if (f[0] == "cpu") st.total = t;
            else st.cores.push_back(t);
        } else if (f[0] == "ctxt" && f.size() > 1) {
            st.ctxt = to_num<uint64_t>(f[1]);
        } else if (f[0] == "btime" && f.size() > 1) {
            st.btime = to_num<uint64_t>(f[1]);
        } else if (f[0] == "procs_running" && f.size() > 1) {
            st.procs_running = to_num<int>(f[1]);
        }
    });
    return st;
}

CoreUsage compute_core_usage(const CpuTimes& prev, const CpuTimes& cur, int core) {
    CoreUsage u;
    u.core = core;
    const double total = static_cast<double>(delta(prev.total(), cur.total()));
    if (total <= 0) return u;
    const double idle = static_cast<double>(delta(prev.idle_all(), cur.idle_all()));
    u.usage_pct = std::clamp(pct(total - idle, total), 0.0, 100.0);
    u.user_pct = pct(static_cast<double>(delta(prev.user, cur.user) + delta(prev.nice, cur.nice)), total);
    u.system_pct = pct(static_cast<double>(delta(prev.system, cur.system) + delta(prev.irq, cur.irq) +
                                           delta(prev.softirq, cur.softirq)),
                       total);
    u.iowait_pct = pct(static_cast<double>(delta(prev.iowait, cur.iowait)), total);
    return u;
}

// ------------------------------------------------ /proc/loadavg, uptime ---
LoadAvg parse_loadavg(std::string_view text) {
    const auto f = split_ws(text.substr(0, text.find('\n')));
    LoadAvg l;
    if (f.size() >= 3) {
        l.l1 = to_double(f[0]);
        l.l5 = to_double(f[1]);
        l.l15 = to_double(f[2]);
    }
    return l;
}

double parse_uptime(std::string_view text) {
    const auto f = split_ws(text.substr(0, text.find('\n')));
    return f.empty() ? 0.0 : to_double(f[0]);
}

// --------------------------------------------------------- /proc/meminfo ---
MemorySnapshot parse_meminfo(std::string_view text) {
    MemorySnapshot m;
    bool have_available = false;
    for_each_line(text, [&](std::string_view line) {
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) return;
        const auto key = line.substr(0, colon);
        const auto f = split_ws(line.substr(colon + 1));
        if (f.empty()) return;
        const auto v = to_num<uint64_t>(f[0]);
        if (key == "MemTotal") m.total_kb = v;
        else if (key == "MemFree") m.free_kb = v;
        else if (key == "MemAvailable") { m.available_kb = v; have_available = true; }
        else if (key == "Buffers") m.buffers_kb = v;
        else if (key == "Cached") m.cached_kb = v;
        else if (key == "SwapTotal") m.swap_total_kb = v;
        else if (key == "SwapFree") m.swap_free_kb = v;
    });
    if (!have_available)  // kernels < 3.14
        m.available_kb = m.free_kb + m.buffers_kb + m.cached_kb;
    m.used_kb = m.total_kb > m.available_kb ? m.total_kb - m.available_kb : 0;
    m.swap_used_kb = m.swap_total_kb > m.swap_free_kb ? m.swap_total_kb - m.swap_free_kb : 0;
    m.used_pct = pct(static_cast<double>(m.used_kb), static_cast<double>(m.total_kb));
    m.swap_pct = pct(static_cast<double>(m.swap_used_kb), static_cast<double>(m.swap_total_kb));
    return m;
}

// ------------------------------------------------------- /proc/diskstats ---
std::vector<DiskCounters> parse_diskstats(std::string_view text) {
    std::vector<DiskCounters> out;
    for_each_line(text, [&](std::string_view line) {
        const auto f = split_ws(line);
        // major minor name rd rd_merged rd_sectors rd_ms wr wr_merged wr_sectors wr_ms in_flight io_ms ...
        if (f.size() < 13) return;
        DiskCounters d;
        d.device = std::string(f[2]);
        d.reads_completed = to_num<uint64_t>(f[3]);
        d.sectors_read = to_num<uint64_t>(f[5]);
        d.writes_completed = to_num<uint64_t>(f[7]);
        d.sectors_written = to_num<uint64_t>(f[9]);
        d.io_ms = to_num<uint64_t>(f[12]);
        out.push_back(std::move(d));
    });
    return out;
}

// --------------------------------------------------------- /proc/net/dev ---
std::vector<NetCounters> parse_net_dev(std::string_view text) {
    std::vector<NetCounters> out;
    for_each_line(text, [&](std::string_view line) {
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) return;  // header lines
        auto name = line.substr(0, colon);
        while (!name.empty() && name.front() == ' ') name.remove_prefix(1);
        const auto f = split_ws(line.substr(colon + 1));
        if (f.size() < 16 || name.empty()) return;
        NetCounters n;
        n.iface = std::string(name);
        n.rx_bytes = to_num<uint64_t>(f[0]);
        n.rx_packets = to_num<uint64_t>(f[1]);
        n.rx_errs = to_num<uint64_t>(f[2]);
        n.rx_drop = to_num<uint64_t>(f[3]);
        n.tx_bytes = to_num<uint64_t>(f[8]);
        n.tx_packets = to_num<uint64_t>(f[9]);
        n.tx_errs = to_num<uint64_t>(f[10]);
        n.tx_drop = to_num<uint64_t>(f[11]);
        out.push_back(std::move(n));
    });
    return out;
}

// ------------------------------------------------------- /proc/net/tcp* ---
void accumulate_proc_net_tcp(std::string_view text, TcpSummary& out) {
    bool header = true;
    for_each_line(text, [&](std::string_view line) {
        if (header) { header = false; return; }
        const auto f = split_ws(line);
        // sl local_address rem_address st ...
        if (f.size() < 4) return;
        unsigned state = 0;
        std::from_chars(f[3].data(), f[3].data() + f[3].size(), state, 16);
        ++out.total;
        switch (state) {
            case 0x01: ++out.established; break;
            case 0x06: ++out.time_wait; break;
            case 0x0A: {
                ++out.listen;
                const auto colon = f[1].rfind(':');
                if (colon != std::string_view::npos) {
                    unsigned port = 0;
                    const auto p = f[1].substr(colon + 1);
                    std::from_chars(p.data(), p.data() + p.size(), port, 16);
                    if (port > 0 && port <= 0xFFFF) out.listen_ports.insert(static_cast<uint16_t>(port));
                }
                break;
            }
            default: break;
        }
    });
}

// -------------------------------------------------------- /proc/<pid>/* ---
std::optional<PidStat> parse_pid_stat(std::string_view text) {
    // The comm field is wrapped in parentheses and may itself contain
    // spaces or ')' -- so locate the *last* closing parenthesis.
    const auto open = text.find('(');
    const auto close = text.rfind(')');
    if (open == std::string_view::npos || close == std::string_view::npos || close < open) return std::nullopt;

    PidStat s;
    s.pid = to_num<int>(text.substr(0, open > 0 ? open - 1 : 0));
    s.comm = std::string(text.substr(open + 1, close - open - 1));

    const auto f = split_ws(text.substr(close + 1));
    // f[0] is field 3 (state); field N is f[N - 3].
    if (f.size() < 22) return std::nullopt;
    s.state = f[0].empty() ? '?' : f[0][0];
    s.ppid = to_num<int>(f[1]);
    s.utime = to_num<uint64_t>(f[11]);
    s.stime = to_num<uint64_t>(f[12]);
    s.num_threads = to_num<int>(f[17]);
    s.starttime = to_num<uint64_t>(f[19]);
    s.vsize = to_num<uint64_t>(f[20]);
    s.rss_pages = to_num<int64_t>(f[21]);
    return s;
}

std::optional<uint32_t> parse_status_uid(std::string_view text) {
    std::optional<uint32_t> uid;
    for_each_line(text, [&](std::string_view line) {
        if (uid || line.substr(0, 4) != "Uid:") return;
        const auto f = split_ws(line.substr(4));
        if (!f.empty()) uid = to_num<uint32_t>(f[0]);  // real uid
    });
    return uid;
}

std::string normalize_cmdline(std::string raw, std::size_t max_len) {
    while (!raw.empty() && raw.back() == '\0') raw.pop_back();
    std::replace(raw.begin(), raw.end(), '\0', ' ');
    if (raw.size() > max_len) raw.resize(max_len);
    return raw;
}

// ----------------------------------------------------------- /proc/mounts ---
std::vector<MountEntry> parse_mounts(std::string_view text) {
    std::vector<MountEntry> out;
    for_each_line(text, [&](std::string_view line) {
        const auto f = split_ws(line);
        if (f.size() < 3) return;
        MountEntry m{std::string(f[0]), std::string(f[1]), std::string(f[2])};
        // Mount points encode spaces as \040.
        std::string& mp = m.mount_point;
        for (std::size_t p; (p = mp.find("\\040")) != std::string::npos;) mp.replace(p, 4, " ");
        out.push_back(std::move(m));
    });
    return out;
}

// --------------------------------------------------------- auth failures ---
std::optional<AuthFailure> parse_auth_failure(std::string_view line_sv) {
    static const std::regex ssh_failed(
        R"(sshd\[\d+\]: Failed (?:password|publickey|keyboard-interactive/pam|none) for (invalid user )?(\S+) from (\S+))");
    static const std::regex pam_failure(
        R"((\w[\w-]*)(?:\[\d+\])?: pam_unix\(([\w-]+):auth\): authentication failure;.*?rhost=(\S*)(?:\s+user=(\S+))?)");
    static const std::regex su_failed(R"(su(?:\[\d+\])?: FAILED (?:SU|su) (?:\(to (\S+)\) )?(\S+))");

    const std::string line(line_sv);
    std::smatch m;
    if (std::regex_search(line, m, ssh_failed)) {
        AuthFailure a;
        a.service = "sshd";
        a.invalid_user = m[1].matched;
        a.user = m[2].str();
        a.ip = m[3].str();
        return a;
    }
    if (std::regex_search(line, m, pam_failure)) {
        const std::string service = m[2].str();
        // sshd failures are already reported by the "Failed password" line.
        if (service == "sshd" || m[1].str() == "sshd") return std::nullopt;
        AuthFailure a;
        a.service = service;
        a.ip = m[3].str();
        a.user = m[4].matched ? m[4].str() : "";
        return a;
    }
    if (std::regex_search(line, m, su_failed)) {
        AuthFailure a;
        a.service = "su";
        a.user = m[1].matched ? m[1].str() : m[2].str();
        return a;
    }
    return std::nullopt;
}

}  // namespace sysmon::parsers
