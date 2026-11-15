#pragma once

#include <memory>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collectors/collectors.hpp"
#include "core/blocking_queue.hpp"
#include "core/config.hpp"
#include "core/thread_pool.hpp"
#include "core/types.hpp"
#include "security/alert_manager.hpp"
#include "security/auth_log_monitor.hpp"
#include "security/security_detector.hpp"

namespace sysmon {

class Database;
class LiveServer;

/// The collection engine.
///
///   control thread ── every interval ──▶ ThreadPool (one task per collector)
///        │                                  cpu │ mem │ disk │ net │ procs
///        ▼
///   MetricsFrame ─▶ SecurityDetector / AlertManager ─▶ events + alerts
///        │
///        ├─▶ LiveServer::broadcast   (Boost.Asio thread)
///        └─▶ BlockingQueue<DbJob> ─▶ DB writer thread ─▶ PostgreSQL
///
///   AuthLogMonitor thread ─▶ BlockingQueue<AuthFailure> ─▶ control thread
class Engine {
public:
    Engine(Config cfg, std::shared_ptr<Database> db, LiveServer* live);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    /// Runs until `st` is signalled. Blocks the calling thread.
    void run(std::stop_token st);

    /// Samples all collectors in parallel and returns one frame.
    MetricsFrame collect();

    const std::string& hostname() const { return hostname_; }

private:
    struct DbJob {
        MetricsFrame frame;
        int store_processes = 0;
        std::vector<SecurityEvent> events;
        std::vector<Alert> alerts;
    };
    using TimedAuthFailure = std::pair<parsers::AuthFailure, TimePoint>;

    void db_writer_loop(std::stop_token st);
    bool write_job(const DbJob& job);

    Config cfg_;
    std::string hostname_;
    std::shared_ptr<Database> db_;
    LiveServer* live_;

    ThreadPool pool_;
    CpuCollector cpu_;
    MemoryCollector memory_;
    DiskCollector disk_;
    NetworkCollector network_;
    ProcessCollector processes_;

    SecurityDetector detector_;
    AlertManager alert_manager_;
    BlockingQueue<TimedAuthFailure> auth_queue_{4096};
    std::unique_ptr<AuthLogMonitor> auth_monitor_;

    BlockingQueue<DbJob> db_queue_;
    uint64_t sequence_ = 0;
    std::jthread db_thread_;  // declared last so it is joined before the members it uses are destroyed
};

}  // namespace sysmon
