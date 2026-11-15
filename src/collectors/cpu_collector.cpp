#include "collectors/collectors.hpp"

namespace sysmon {

CpuCollector::CpuCollector(std::string proc_root) : root_(std::move(proc_root)) {
    // Prime the counters so the very first sample() already reports a real delta.
    if (auto text = parsers::read_file(root_ + "/stat")) prev_ = parsers::parse_proc_stat(*text);
    prev_time_ = SteadyClock::now();
}

CpuSnapshot CpuCollector::sample() {
    CpuSnapshot snap;
    const auto now = SteadyClock::now();

    if (auto text = parsers::read_file(root_ + "/stat")) {
        const auto cur = parsers::parse_proc_stat(*text);
        snap.total_pct = parsers::compute_core_usage(prev_.total, cur.total, -1).usage_pct;
        snap.cores.reserve(cur.cores.size());
        for (std::size_t i = 0; i < cur.cores.size(); ++i) {
            const CpuTimes prev = i < prev_.cores.size() ? prev_.cores[i] : CpuTimes{};
            snap.cores.push_back(parsers::compute_core_usage(prev, cur.cores[i], static_cast<int>(i)));
        }
        const double secs = std::chrono::duration<double>(now - prev_time_).count();
        if (secs > 0 && cur.ctxt >= prev_.ctxt)
            snap.ctx_switches_per_s = static_cast<double>(cur.ctxt - prev_.ctxt) / secs;
        prev_ = cur;
    }
    prev_time_ = now;

    if (auto text = parsers::read_file(root_ + "/loadavg")) {
        const auto l = parsers::parse_loadavg(*text);
        snap.load1 = l.l1;
        snap.load5 = l.l5;
        snap.load15 = l.l15;
    }
    if (auto text = parsers::read_file(root_ + "/uptime")) snap.uptime_s = parsers::parse_uptime(*text);
    return snap;
}

}  // namespace sysmon
