#include <pwd.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <unordered_set>

#include "collectors/collectors.hpp"

namespace sysmon {
namespace fs = std::filesystem;

ProcessCollector::ProcessCollector(std::string proc_root)
    : root_(std::move(proc_root)),
      clk_tck_(std::max(1L, ::sysconf(_SC_CLK_TCK))),
      page_kb_(std::max(1L, ::sysconf(_SC_PAGESIZE) / 1024)) {
    if (auto text = parsers::read_file(root_ + "/stat")) btime_ = parsers::parse_proc_stat(*text).btime;
    prev_time_ = SteadyClock::now();
}

std::string ProcessCollector::username(uint32_t uid) {
    if (auto it = users_.find(uid); it != users_.end()) return it->second;
    std::string name = std::to_string(uid);
    struct passwd pw {};
    struct passwd* result = nullptr;
    std::vector<char> buf(16384);
    if (::getpwuid_r(uid, &pw, buf.data(), buf.size(), &result) == 0 && result) name = result->pw_name;
    users_.emplace(uid, name);
    return name;
}

ProcessSnapshot ProcessCollector::sample() {
    ProcessSnapshot snap;
    const auto now = SteadyClock::now();
    const double secs = std::chrono::duration<double>(now - prev_time_).count();
    std::unordered_map<int, Prev> current;

    std::error_code ec;
    for (fs::directory_iterator it(root_, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string pid_str = it->path().filename().string();
        if (pid_str.empty() || !std::all_of(pid_str.begin(), pid_str.end(), ::isdigit)) continue;

        const fs::path dir = it->path();
        const auto stat_text = parsers::read_file(dir / "stat");
        if (!stat_text) continue;  // process exited
        const auto st = parsers::parse_pid_stat(*stat_text);
        if (!st) continue;

        ProcessInfo p;
        p.pid = st->pid;
        p.ppid = st->ppid;
        p.name = st->comm;
        p.state = st->state;
        p.threads = st->num_threads;
        p.vsize_kb = st->vsize / 1024;
        p.rss_kb = st->rss_pages > 0 ? static_cast<uint64_t>(st->rss_pages) * static_cast<uint64_t>(page_kb_) : 0;
        p.start_ticks = st->starttime;
        p.start_time = static_cast<double>(btime_) + static_cast<double>(st->starttime) / static_cast<double>(clk_tck_);

        const uint64_t ticks = st->utime + st->stime;
        // Only compare against the previous sample if it is the *same* process
        // (pids get recycled; start time disambiguates).
        if (auto prev = prev_.find(p.pid); prev != prev_.end() && prev->second.start == st->starttime && secs > 0) {
            const uint64_t d = ticks >= prev->second.ticks ? ticks - prev->second.ticks : 0;
            p.cpu_pct = 100.0 * (static_cast<double>(d) / static_cast<double>(clk_tck_)) / secs;
        }
        current[p.pid] = Prev{ticks, st->starttime};

        if (auto status = parsers::read_file(dir / "status"))
            if (auto uid = parsers::parse_status_uid(*status)) {
                p.uid = *uid;
                p.user = username(*uid);
            }
        if (auto cmd = parsers::read_file(dir / "cmdline")) p.cmdline = parsers::normalize_cmdline(std::move(*cmd));
        if (p.cmdline.empty()) p.cmdline = "[" + p.name + "]";  // kernel thread

        std::error_code exe_ec;
        const auto exe = fs::read_symlink(dir / "exe", exe_ec);
        if (!exe_ec) p.exe = exe.string();

        ++snap.total;
        if (p.state == 'R') ++snap.running;
        snap.threads += p.threads;
        snap.processes.push_back(std::move(p));
    }

    prev_ = std::move(current);
    prev_time_ = now;

    std::sort(snap.processes.begin(), snap.processes.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
        if (a.cpu_pct != b.cpu_pct) return a.cpu_pct > b.cpu_pct;
        return a.rss_kb > b.rss_kb;
    });
    return snap;
}

}  // namespace sysmon
