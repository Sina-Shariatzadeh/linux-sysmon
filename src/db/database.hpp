#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "core/types.hpp"

namespace pqxx {
class connection;
}

namespace sysmon {

/// Historical metrics that the analytics queries can aggregate.
enum class HistoryMetric {
    CpuTotal,
    MemoryUsed,
    SwapUsed,
    Load1,
    NetRx,
    NetTx,
    DiskRead,
    DiskWrite,
    ProcessCount,
    TcpEstablished,
};

const char* to_label(HistoryMetric m);  ///< human readable, includes unit

struct SeriesPoint {
    double ts = 0;   ///< bucket start, epoch seconds
    double avg = 0;
    double max = 0;
    double min = 0;
};

struct ProcessStat {
    std::string name;
    std::string user;
    long samples = 0;
    double avg_cpu = 0, max_cpu = 0;
    double avg_rss_kb = 0, max_rss_kb = 0;
};

struct EventRow {
    std::string kind;  ///< "security" or "alert"
    long long id = 0;
    double ts = 0;
    std::string severity;
    std::string subject;  ///< category or metric
    std::string message;
};

struct PeriodSummary {
    long samples = 0;
    double avg_cpu = 0, max_cpu = 0;
    double avg_mem = 0, max_mem = 0;
    double avg_load1 = 0;
    long security_events = 0, critical_events = 0, alerts = 0;
};

/// Thread-safe PostgreSQL access via libpqxx. Reconnects transparently if
/// the server restarts; write methods throw on failure so the caller can
/// decide whether to retry or drop.
class Database {
public:
    explicit Database(std::string conninfo);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    bool is_connected();
    void apply_schema_file(const std::string& path);

    // ---- writes ------------------------------------------------------
    /// Stores one frame. When `top_processes` > 0 the top-N processes are
    /// stored as well. Returns the system_metrics id.
    long long insert_frame(const MetricsFrame& frame, int top_processes);
    void insert_events(const std::vector<SecurityEvent>& events, const std::string& hostname);
    void insert_alerts(const std::vector<Alert>& alerts, const std::string& hostname);
    /// Deletes data older than `days`; returns number of snapshots removed.
    long long purge_older_than(int days);

    // ---- analytics ---------------------------------------------------
    std::vector<SeriesPoint> metric_history(HistoryMetric m, TimePoint from, TimePoint to, int bucket_seconds);
    std::vector<ProcessStat> process_stats(TimePoint from, TimePoint to, int limit);
    std::vector<EventRow> search_events(const std::string& text, Severity min_severity, TimePoint from, TimePoint to,
                                        int limit);
    PeriodSummary summary(TimePoint from, TimePoint to);

private:
    pqxx::connection& conn();  ///< caller must hold mutex_
    void prepare_statements();

    std::string conninfo_;
    std::unique_ptr<pqxx::connection> conn_;
    std::mutex mutex_;
};

}  // namespace sysmon
