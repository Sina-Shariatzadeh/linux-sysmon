#include "core/json.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <sstream>

namespace sysmon::json {

std::string escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(ch);
                }
        }
    }
    out.push_back('"');
    return out;
}

std::string number(double v) {
    if (!std::isfinite(v)) return "0";
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.10g", v);
    return buf;
}

std::string timestamp(double epoch_s) {
    if (!std::isfinite(epoch_s)) return "0";
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.3f", epoch_s);
    return buf;
}

namespace {

/// Tiny helper that keeps track of commas between object members.
class Obj {
public:
    explicit Obj(std::ostringstream& os) : os_(os) { os_ << '{'; }
    ~Obj() { os_ << '}'; }
    Obj(const Obj&) = delete;
    Obj& operator=(const Obj&) = delete;

    std::ostringstream& key(std::string_view k) {
        if (!first_) os_ << ',';
        first_ = false;
        os_ << escape(k) << ':';
        return os_;
    }
    void str(std::string_view k, std::string_view v) { key(k) << escape(v); }
    void num(std::string_view k, double v) { key(k) << number(v); }
    void integer(std::string_view k, long long v) { key(k) << v; }
    void ts(std::string_view k, TimePoint t) { key(k) << timestamp(to_epoch_seconds(t)); }

private:
    std::ostringstream& os_;
    bool first_ = true;
};

}  // namespace

std::string to_json(const MetricsFrame& f, int max_processes) {
    std::ostringstream os;
    {
        Obj root(os);
        root.str("type", "frame");
        root.ts("ts", f.ts);
        root.str("host", f.hostname);
        root.integer("seq", static_cast<long long>(f.sequence));

        {  // cpu
            root.key("cpu");
            Obj cpu(os);
            cpu.num("total", f.cpu.total_pct);
            cpu.num("load1", f.cpu.load1);
            cpu.num("load5", f.cpu.load5);
            cpu.num("load15", f.cpu.load15);
            cpu.num("uptime", f.cpu.uptime_s);
            cpu.num("ctxt_ps", f.cpu.ctx_switches_per_s);
            cpu.key("cores") << '[';
            for (std::size_t i = 0; i < f.cpu.cores.size(); ++i) {
                if (i) os << ',';
                Obj c(os);
                c.integer("core", f.cpu.cores[i].core);
                c.num("usage", f.cpu.cores[i].usage_pct);
                c.num("user", f.cpu.cores[i].user_pct);
                c.num("system", f.cpu.cores[i].system_pct);
                c.num("iowait", f.cpu.cores[i].iowait_pct);
            }
            os << ']';
        }
        {  // memory
            root.key("memory");
            Obj m(os);
            const auto& mem = f.memory;
            m.integer("total_kb", static_cast<long long>(mem.total_kb));
            m.integer("used_kb", static_cast<long long>(mem.used_kb));
            m.integer("available_kb", static_cast<long long>(mem.available_kb));
            m.integer("cached_kb", static_cast<long long>(mem.cached_kb));
            m.integer("buffers_kb", static_cast<long long>(mem.buffers_kb));
            m.integer("swap_total_kb", static_cast<long long>(mem.swap_total_kb));
            m.integer("swap_used_kb", static_cast<long long>(mem.swap_used_kb));
            m.num("used_pct", mem.used_pct);
            m.num("swap_pct", mem.swap_pct);
        }
        {  // disk
            root.key("disk");
            Obj d(os);
            d.key("io") << '[';
            for (std::size_t i = 0; i < f.disk.io.size(); ++i) {
                if (i) os << ',';
                const auto& io = f.disk.io[i];
                Obj o(os);
                o.str("device", io.device);
                o.num("read_bps", io.read_bps);
                o.num("write_bps", io.write_bps);
                o.num("reads_ps", io.reads_ps);
                o.num("writes_ps", io.writes_ps);
                o.num("util", io.util_pct);
            }
            os << ']';
            d.key("fs") << '[';
            for (std::size_t i = 0; i < f.disk.filesystems.size(); ++i) {
                if (i) os << ',';
                const auto& fs = f.disk.filesystems[i];
                Obj o(os);
                o.str("mount", fs.mount_point);
                o.str("device", fs.device);
                o.str("type", fs.fs_type);
                o.num("total", static_cast<double>(fs.total_bytes));
                o.num("used", static_cast<double>(fs.used_bytes));
                o.num("used_pct", fs.used_pct);
            }
            os << ']';
        }
        {  // network
            root.key("network");
            Obj n(os);
            n.num("rx_bps", f.network.total_rx_bps);
            n.num("tx_bps", f.network.total_tx_bps);
            n.integer("tcp_established", f.network.tcp_established);
            n.integer("tcp_listen", f.network.tcp_listen);
            n.integer("tcp_time_wait", f.network.tcp_time_wait);
            n.key("listen_ports") << '[';
            for (std::size_t i = 0; i < f.network.listen_ports.size(); ++i)
                os << (i ? "," : "") << f.network.listen_ports[i];
            os << ']';
            n.key("interfaces") << '[';
            for (std::size_t i = 0; i < f.network.interfaces.size(); ++i) {
                if (i) os << ',';
                const auto& r = f.network.interfaces[i];
                Obj o(os);
                o.str("iface", r.iface);
                o.num("rx_bps", r.rx_bps);
                o.num("tx_bps", r.tx_bps);
                o.num("rx_pps", r.rx_pps);
                o.num("tx_pps", r.tx_pps);
                o.integer("rx_errs", static_cast<long long>(r.rx_errs));
                o.integer("tx_errs", static_cast<long long>(r.tx_errs));
            }
            os << ']';
        }
        {  // processes
            root.key("processes");
            Obj p(os);
            p.integer("total", f.processes.total);
            p.integer("running", f.processes.running);
            p.integer("threads", f.processes.threads);
            p.key("top") << '[';
            const std::size_t n =
                std::min(f.processes.processes.size(), static_cast<std::size_t>(std::max(0, max_processes)));
            for (std::size_t i = 0; i < n; ++i) {
                if (i) os << ',';
                const auto& pr = f.processes.processes[i];
                Obj o(os);
                o.integer("pid", pr.pid);
                o.integer("ppid", pr.ppid);
                o.str("name", pr.name);
                o.str("user", pr.user);
                o.str("state", std::string(1, pr.state));
                o.num("cpu", pr.cpu_pct);
                o.integer("rss_kb", static_cast<long long>(pr.rss_kb));
                o.integer("threads", pr.threads);
                o.str("cmd", pr.cmdline);
            }
            os << ']';
        }
    }
    return os.str();
}

std::string to_json(const SecurityEvent& e) {
    std::ostringstream os;
    {
        Obj o(os);
        o.str("type", "event");
        o.ts("ts", e.ts);
        o.str("severity", to_string(e.severity));
        o.str("category", e.category);
        o.str("source", e.source);
        o.str("message", e.message);
        if (e.pid) o.integer("pid", *e.pid);
        o.key("details") << (e.details_json.empty() ? "{}" : e.details_json);
    }
    return os.str();
}

std::string to_json(const Alert& a) {
    std::ostringstream os;
    {
        Obj o(os);
        o.str("type", "alert");
        o.ts("ts", a.ts);
        o.str("severity", to_string(a.severity));
        o.str("metric", a.metric);
        o.num("value", a.value);
        o.num("threshold", a.threshold);
        o.str("message", a.message);
        o.key("resolved") << (a.resolved ? "true" : "false");
    }
    return os.str();
}

}  // namespace sysmon::json
