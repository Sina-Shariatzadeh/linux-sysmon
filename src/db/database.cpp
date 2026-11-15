#include "db/database.hpp"

#include <algorithm>
#include <fstream>
#include <pqxx/pqxx>
#include <sstream>
#include <stdexcept>

namespace sysmon {
namespace {

/// Escapes LIKE wildcards so user search text is matched literally.
std::string like_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '%' || c == '_') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

const char* kTimeFilter = " ts >= to_timestamp($1::float8) AND ts < to_timestamp($2::float8) ";

}  // namespace

const char* to_label(HistoryMetric m) {
    switch (m) {
        case HistoryMetric::CpuTotal: return "CPU usage (%)";
        case HistoryMetric::MemoryUsed: return "Memory used (%)";
        case HistoryMetric::SwapUsed: return "Swap used (%)";
        case HistoryMetric::Load1: return "Load average (1 min)";
        case HistoryMetric::NetRx: return "Network RX (bytes/s)";
        case HistoryMetric::NetTx: return "Network TX (bytes/s)";
        case HistoryMetric::DiskRead: return "Disk read (bytes/s)";
        case HistoryMetric::DiskWrite: return "Disk write (bytes/s)";
        case HistoryMetric::ProcessCount: return "Process count";
        case HistoryMetric::TcpEstablished: return "Established TCP connections";
    }
    return "";
}

Database::Database(std::string conninfo) : conninfo_(std::move(conninfo)) {}
Database::~Database() = default;

pqxx::connection& Database::conn() {
    if (!conn_ || !conn_->is_open()) {
        conn_ = std::make_unique<pqxx::connection>(conninfo_);
        prepare_statements();
    }
    return *conn_;
}

bool Database::is_connected() {
    std::lock_guard lock(mutex_);
    try {
        return conn().is_open();
    } catch (const std::exception&) {
        conn_.reset();
        return false;
    }
}

void Database::prepare_statements() {
    auto& c = *conn_;
    c.prepare("ins_system",
              "INSERT INTO system_metrics (ts, hostname, cpu_total_pct, load1, load5, load15, mem_used_pct, "
              "swap_used_pct, process_count, running_count, thread_count, tcp_established, uptime_s) "
              "VALUES (to_timestamp($1::float8), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id");
    c.prepare("ins_cpu",
              "INSERT INTO cpu_metrics (snapshot_id, ts, core, usage_pct, user_pct, system_pct, iowait_pct) "
              "VALUES ($1, to_timestamp($2::float8), $3, $4, $5, $6, $7)");
    c.prepare("ins_mem",
              "INSERT INTO memory_metrics (snapshot_id, ts, total_kb, used_kb, available_kb, buffers_kb, cached_kb, "
              "swap_total_kb, swap_used_kb) VALUES ($1, to_timestamp($2::float8), $3, $4, $5, $6, $7, $8, $9)");
    c.prepare("ins_disk",
              "INSERT INTO disk_metrics (snapshot_id, ts, device, read_bps, write_bps, reads_ps, writes_ps, util_pct) "
              "VALUES ($1, to_timestamp($2::float8), $3, $4, $5, $6, $7, $8)");
    c.prepare("ins_fs",
              "INSERT INTO filesystem_metrics (snapshot_id, ts, mount_point, device, fs_type, total_bytes, "
              "used_bytes, used_pct) VALUES ($1, to_timestamp($2::float8), $3, $4, $5, $6, $7, $8)");
    c.prepare("ins_net",
              "INSERT INTO network_metrics (snapshot_id, ts, iface, rx_bps, tx_bps, rx_pps, tx_pps, rx_errors, "
              "tx_errors) VALUES ($1, to_timestamp($2::float8), $3, $4, $5, $6, $7, $8, $9)");
    c.prepare("ins_proc",
              "INSERT INTO processes (snapshot_id, ts, pid, ppid, name, username, state, cpu_pct, rss_kb, threads, "
              "exe, cmdline) VALUES ($1, to_timestamp($2::float8), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)");
    c.prepare("ins_event",
              "INSERT INTO security_events (ts, hostname, severity, category, source, message, pid, details) "
              "VALUES (to_timestamp($1::float8), $2, $3, $4, $5, $6, $7, $8::jsonb)");
    c.prepare("ins_alert",
              "INSERT INTO alerts (ts, hostname, severity, metric, value, threshold, message, resolved) "
              "VALUES (to_timestamp($1::float8), $2, $3, $4, $5, $6, $7, $8)");
}

void Database::apply_schema_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open schema file: " + path);
    std::stringstream ss;
    ss << f.rdbuf();

    std::lock_guard lock(mutex_);
    // Create the connection without preparing statements first: the tables
    // they reference may not exist yet.
    if (!conn_ || !conn_->is_open()) conn_ = std::make_unique<pqxx::connection>(conninfo_);
    {
        pqxx::work tx(*conn_);
        tx.exec(ss.str());
        tx.commit();
    }
    conn_.reset();  // reconnect (and prepare) lazily on next use
}

// ======================================================================
// Writes
// ======================================================================
long long Database::insert_frame(const MetricsFrame& f, int top_processes) {
    std::lock_guard lock(mutex_);
    try {
        pqxx::work tx(conn());
        const double ts = to_epoch_seconds(f.ts);

        const auto id = tx.exec_prepared1("ins_system", ts, f.hostname, f.cpu.total_pct, f.cpu.load1, f.cpu.load5,
                                          f.cpu.load15, f.memory.used_pct, f.memory.swap_pct, f.processes.total,
                                          f.processes.running, f.processes.threads, f.network.tcp_established,
                                          f.cpu.uptime_s)[0]
                            .as<long long>();

        for (const auto& c : f.cpu.cores)
            tx.exec_prepared("ins_cpu", id, ts, c.core, c.usage_pct, c.user_pct, c.system_pct, c.iowait_pct);

        const auto& m = f.memory;
        tx.exec_prepared("ins_mem", id, ts, static_cast<long long>(m.total_kb), static_cast<long long>(m.used_kb),
                         static_cast<long long>(m.available_kb), static_cast<long long>(m.buffers_kb),
                         static_cast<long long>(m.cached_kb), static_cast<long long>(m.swap_total_kb),
                         static_cast<long long>(m.swap_used_kb));

        for (const auto& d : f.disk.io)
            tx.exec_prepared("ins_disk", id, ts, d.device, d.read_bps, d.write_bps, d.reads_ps, d.writes_ps,
                             d.util_pct);
        for (const auto& fs : f.disk.filesystems)
            tx.exec_prepared("ins_fs", id, ts, fs.mount_point, fs.device, fs.fs_type,
                             static_cast<long long>(fs.total_bytes), static_cast<long long>(fs.used_bytes),
                             fs.used_pct);
        for (const auto& n : f.network.interfaces)
            tx.exec_prepared("ins_net", id, ts, n.iface, n.rx_bps, n.tx_bps, n.rx_pps, n.tx_pps,
                             static_cast<long long>(n.rx_errs), static_cast<long long>(n.tx_errs));

        const auto& procs = f.processes.processes;
        const std::size_t n = std::min(procs.size(), static_cast<std::size_t>(std::max(0, top_processes)));
        for (std::size_t i = 0; i < n; ++i) {
            const auto& p = procs[i];
            tx.exec_prepared("ins_proc", id, ts, p.pid, p.ppid, p.name, p.user, std::string(1, p.state), p.cpu_pct,
                             static_cast<long long>(p.rss_kb), p.threads, p.exe, p.cmdline);
        }
        tx.commit();
        return id;
    } catch (const pqxx::broken_connection&) {
        conn_.reset();
        throw;
    }
}

void Database::insert_events(const std::vector<SecurityEvent>& events, const std::string& hostname) {
    if (events.empty()) return;
    std::lock_guard lock(mutex_);
    try {
        pqxx::work tx(conn());
        for (const auto& e : events)
            tx.exec_prepared("ins_event", to_epoch_seconds(e.ts), hostname, std::string(to_string(e.severity)),
                             e.category, e.source, e.message, e.pid, e.details_json.empty() ? "{}" : e.details_json);
        tx.commit();
    } catch (const pqxx::broken_connection&) {
        conn_.reset();
        throw;
    }
}

void Database::insert_alerts(const std::vector<Alert>& alerts, const std::string& hostname) {
    if (alerts.empty()) return;
    std::lock_guard lock(mutex_);
    try {
        pqxx::work tx(conn());
        for (const auto& a : alerts)
            tx.exec_prepared("ins_alert", to_epoch_seconds(a.ts), hostname, std::string(to_string(a.severity)),
                             a.metric, a.value, a.threshold, a.message, a.resolved);
        tx.commit();
    } catch (const pqxx::broken_connection&) {
        conn_.reset();
        throw;
    }
}

long long Database::purge_older_than(int days) {
    std::lock_guard lock(mutex_);
    try {
        pqxx::work tx(conn());
        const auto r = tx.exec_params("DELETE FROM system_metrics WHERE ts < now() - make_interval(days => $1)", days);
        tx.exec_params("DELETE FROM security_events WHERE ts < now() - make_interval(days => $1)", days);
        tx.exec_params("DELETE FROM alerts WHERE ts < now() - make_interval(days => $1)", days);
        tx.commit();
        return static_cast<long long>(r.affected_rows());
    } catch (const pqxx::broken_connection&) {
        conn_.reset();
        throw;
    }
}

// ======================================================================
// Analytics
// ======================================================================
std::vector<SeriesPoint> Database::metric_history(HistoryMetric m, TimePoint from, TimePoint to, int bucket_seconds) {
    // Inner query yields one (ts, v) row per snapshot. The SQL text is built
    // only from fixed fragments selected by the enum -- never from user input.
    std::string inner;
    auto sys = [&](const char* col) {
        inner = std::string("SELECT ts, ") + col + "::float8 AS v FROM system_metrics WHERE" + kTimeFilter;
    };
    auto summed = [&](const char* table, const char* col) {
        inner = std::string("SELECT ts, sum(") + col + ")::float8 AS v FROM " + table + " WHERE" + kTimeFilter +
                "GROUP BY snapshot_id, ts";
    };
    switch (m) {
        case HistoryMetric::CpuTotal: sys("cpu_total_pct"); break;
        case HistoryMetric::MemoryUsed: sys("mem_used_pct"); break;
        case HistoryMetric::SwapUsed: sys("swap_used_pct"); break;
        case HistoryMetric::Load1: sys("load1"); break;
        case HistoryMetric::ProcessCount: sys("process_count"); break;
        case HistoryMetric::TcpEstablished: sys("tcp_established"); break;
        case HistoryMetric::NetRx: summed("network_metrics", "rx_bps"); break;
        case HistoryMetric::NetTx: summed("network_metrics", "tx_bps"); break;
        case HistoryMetric::DiskRead: summed("disk_metrics", "read_bps"); break;
        case HistoryMetric::DiskWrite: summed("disk_metrics", "write_bps"); break;
    }
    const std::string sql =
        "SELECT floor(extract(epoch FROM ts)::float8 / $3::float8) * $3::float8 AS b, "
        "avg(v)::float8, max(v)::float8, min(v)::float8 FROM (" +
        inner + ") s GROUP BY b ORDER BY b";

    std::lock_guard lock(mutex_);
    try {
        pqxx::read_transaction tx(conn());
        const auto r = tx.exec_params(sql, to_epoch_seconds(from), to_epoch_seconds(to), std::max(1, bucket_seconds));
        std::vector<SeriesPoint> out;
        out.reserve(r.size());
        for (const auto& row : r)
            out.push_back({row[0].as<double>(), row[1].as<double>(0.0), row[2].as<double>(0.0), row[3].as<double>(0.0)});
        return out;
    } catch (const pqxx::broken_connection&) {
        conn_.reset();
        throw;
    }
}

std::vector<ProcessStat> Database::process_stats(TimePoint from, TimePoint to, int limit) {
    const std::string sql = std::string(
                                "SELECT name, coalesce(mode() WITHIN GROUP (ORDER BY username), ''), count(*), "
                                "avg(cpu_pct)::float8, max(cpu_pct)::float8, avg(rss_kb)::float8, max(rss_kb)::float8 "
                                "FROM processes WHERE") +
                            kTimeFilter + "GROUP BY name ORDER BY avg(cpu_pct) DESC NULLS LAST LIMIT $3::int";
    std::lock_guard lock(mutex_);
    try {
        pqxx::read_transaction tx(conn());
        const auto r = tx.exec_params(sql, to_epoch_seconds(from), to_epoch_seconds(to), limit);
        std::vector<ProcessStat> out;
        for (const auto& row : r) {
            ProcessStat s;
            s.name = row[0].as<std::string>();
            s.user = row[1].as<std::string>();
            s.samples = row[2].as<long>();
            s.avg_cpu = row[3].as<double>(0.0);
            s.max_cpu = row[4].as<double>(0.0);
            s.avg_rss_kb = row[5].as<double>(0.0);
            s.max_rss_kb = row[6].as<double>(0.0);
            out.push_back(std::move(s));
        }
        return out;
    } catch (const pqxx::broken_connection&) {
        conn_.reset();
        throw;
    }
}

std::vector<EventRow> Database::search_events(const std::string& text, Severity min_severity, TimePoint from,
                                              TimePoint to, int limit) {
    const std::string sql = std::string(
                                "SELECT kind, id, extract(epoch FROM ts)::float8, severity, subject, message "
                                "FROM v_event_log WHERE") +
                            kTimeFilter +
                            "AND (CASE severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END) >= $3::int "
                            "AND ($4::text = '' OR message ILIKE '%' || $4::text || '%' "
                            "OR subject ILIKE '%' || $4::text || '%') "
                            "ORDER BY ts DESC LIMIT $5::int";
    std::lock_guard lock(mutex_);
    try {
        pqxx::read_transaction tx(conn());
        const auto r = tx.exec_params(sql, to_epoch_seconds(from), to_epoch_seconds(to),
                                      static_cast<int>(min_severity), like_escape(text), limit);
        std::vector<EventRow> out;
        for (const auto& row : r) {
            EventRow e;
            e.kind = row[0].as<std::string>();
            e.id = row[1].as<long long>();
            e.ts = row[2].as<double>();
            e.severity = row[3].as<std::string>();
            e.subject = row[4].as<std::string>();
            e.message = row[5].as<std::string>();
            out.push_back(std::move(e));
        }
        return out;
    } catch (const pqxx::broken_connection&) {
        conn_.reset();
        throw;
    }
}

PeriodSummary Database::summary(TimePoint from, TimePoint to) {
    const std::string tf = kTimeFilter;
    const std::string sql =
        "SELECT count(*), coalesce(avg(cpu_total_pct), 0)::float8, coalesce(max(cpu_total_pct), 0)::float8, "
        "coalesce(avg(mem_used_pct), 0)::float8, coalesce(max(mem_used_pct), 0)::float8, "
        "coalesce(avg(load1), 0)::float8, "
        "(SELECT count(*) FROM security_events WHERE" + tf + "), "
        "(SELECT count(*) FROM security_events WHERE severity = 'critical' AND" + tf + "), "
        "(SELECT count(*) FROM alerts WHERE NOT resolved AND" + tf + ") "
        "FROM system_metrics WHERE" + tf;
    std::lock_guard lock(mutex_);
    try {
        pqxx::read_transaction tx(conn());
        const auto row = tx.exec_params1(sql, to_epoch_seconds(from), to_epoch_seconds(to));
        PeriodSummary s;
        s.samples = row[0].as<long>();
        s.avg_cpu = row[1].as<double>();
        s.max_cpu = row[2].as<double>();
        s.avg_mem = row[3].as<double>();
        s.max_mem = row[4].as<double>();
        s.avg_load1 = row[5].as<double>();
        s.security_events = row[6].as<long>();
        s.critical_events = row[7].as<long>();
        s.alerts = row[8].as<long>();
        return s;
    } catch (const pqxx::broken_connection&) {
        conn_.reset();
        throw;
    }
}

}  // namespace sysmon
