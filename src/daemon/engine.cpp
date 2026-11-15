#include "daemon/engine.hpp"

#include <unistd.h>

#include <condition_variable>
#include <future>

#include "core/json.hpp"
#include "core/log.hpp"
#include "daemon/live_server.hpp"
#include "db/database.hpp"

namespace sysmon {
namespace {

std::string system_hostname() {
    char buf[256] = {};
    if (::gethostname(buf, sizeof buf - 1) != 0) return "localhost";
    return buf;
}

/// Waits for a future and logs (instead of propagating) collector failures,
/// so one broken data source never stops the others.
template <typename T>
T get_or_default(std::future<T>& fut, const char* what) {
    try {
        return fut.get();
    } catch (const std::exception& e) {
        log::warn(what, " collector failed: ", e.what());
        return T{};
    }
}

void interruptible_sleep_until(std::stop_token st, std::chrono::steady_clock::time_point deadline) {
    std::mutex m;
    std::condition_variable_any cv;
    std::unique_lock lock(m);
    cv.wait_until(lock, st, deadline, [] { return false; });
}

}  // namespace

Engine::Engine(Config cfg, std::shared_ptr<Database> db, LiveServer* live)
    : cfg_(std::move(cfg)),
      hostname_(cfg_.hostname.empty() ? system_hostname() : cfg_.hostname),
      db_(std::move(db)),
      live_(live),
      pool_(static_cast<std::size_t>(cfg_.worker_threads)),
      cpu_(cfg_.proc_root),
      memory_(cfg_.proc_root),
      disk_(cfg_.proc_root, cfg_.sys_root),
      network_(cfg_.proc_root, cfg_.include_loopback),
      processes_(cfg_.proc_root),
      detector_(cfg_),
      alert_manager_(cfg_),
      db_queue_(static_cast<std::size_t>(std::max(1, cfg_.db_queue_capacity))) {}

Engine::~Engine() {
    if (auth_monitor_) auth_monitor_->stop();
    db_queue_.close();
    if (db_thread_.joinable()) {
        db_thread_.request_stop();
        db_thread_.join();
    }
}

MetricsFrame Engine::collect() {
    // Fan out: every collector owns its own state, so they can run concurrently.
    auto f_cpu = pool_.submit([this] { return cpu_.sample(); });
    auto f_mem = pool_.submit([this] { return memory_.sample(); });
    auto f_disk = pool_.submit([this] { return disk_.sample(); });
    auto f_net = pool_.submit([this] { return network_.sample(); });
    auto f_proc = pool_.submit([this] { return processes_.sample(); });

    MetricsFrame f;
    f.ts = Clock::now();
    f.hostname = hostname_;
    f.sequence = ++sequence_;
    f.cpu = get_or_default(f_cpu, "cpu");
    f.memory = get_or_default(f_mem, "memory");
    f.disk = get_or_default(f_disk, "disk");
    f.network = get_or_default(f_net, "network");
    f.processes = get_or_default(f_proc, "process");
    return f;
}

void Engine::run(std::stop_token st) {
    log::info("engine started on host '", hostname_, "' interval=", cfg_.interval.count(), "ms workers=", pool_.size());

    if (db_) db_thread_ = std::jthread([this](std::stop_token s) { db_writer_loop(s); });

    auth_monitor_ = std::make_unique<AuthLogMonitor>(cfg_.auth_log_paths, [this](const parsers::AuthFailure& a) {
        auth_queue_.push({a, Clock::now()});
    });
    auth_monitor_->start();

    // Discard the first process sample: per-process CPU needs two samples.
    (void)processes_.sample();
    auto next = std::chrono::steady_clock::now() + cfg_.interval;
    interruptible_sleep_until(st, next);

    while (!st.stop_requested()) {
        const auto cycle_start = std::chrono::steady_clock::now();
        MetricsFrame frame = collect();

        // ---- event processing ---------------------------------------
        std::vector<SecurityEvent> events = detector_.analyze(frame);
        while (auto af = auth_queue_.pop_for(std::chrono::milliseconds(0))) {
            auto ev = detector_.on_auth_failure(af->first, af->second);
            events.insert(events.end(), std::make_move_iterator(ev.begin()), std::make_move_iterator(ev.end()));
        }
        std::vector<Alert> alerts = alert_manager_.evaluate(frame);

        for (const auto& e : events)
            if (e.severity != Severity::Info) log::warn("[", to_string(e.severity), "] ", e.category, ": ", e.message);
        for (const auto& a : alerts) log::warn("[alert ", to_string(a.severity), "] ", a.message);

        // ---- live stream --------------------------------------------
        if (live_) {
            live_->broadcast(json::to_json(frame, cfg_.live_top_n), /*remember=*/true);
            for (const auto& e : events) live_->broadcast(json::to_json(e));
            for (const auto& a : alerts) live_->broadcast(json::to_json(a));
        }

        // ---- persistence (asynchronous) -----------------------------
        if (db_) {
            DbJob job;
            const bool with_procs = frame.sequence % static_cast<uint64_t>(cfg_.process_store_every) == 0;
            job.store_processes = with_procs ? cfg_.process_top_n : 0;
            auto& procs = frame.processes.processes;
            if (procs.size() > static_cast<std::size_t>(job.store_processes))
                procs.resize(static_cast<std::size_t>(job.store_processes));  // keep the queued copy small
            job.frame = std::move(frame);
            job.events = std::move(events);
            job.alerts = std::move(alerts);
            if (!db_queue_.push(std::move(job)))
                log::warn("database queue full, dropped oldest frame (", db_queue_.dropped(), " total)");
        }

        // ---- pacing -------------------------------------------------
        next += cfg_.interval;
        const auto now = std::chrono::steady_clock::now();
        if (now > next) {
            log::warn("collection cycle overran interval (took ",
                      std::chrono::duration_cast<std::chrono::milliseconds>(now - cycle_start).count(), "ms)");
            next = now + cfg_.interval;
        }
        interruptible_sleep_until(st, next);
    }

    log::info("engine stopping");
    auth_monitor_->stop();
    db_queue_.close();  // writer drains what is left, then exits
    if (db_thread_.joinable()) db_thread_.join();
}

bool Engine::write_job(const DbJob& job) {
    try {
        db_->insert_frame(job.frame, job.store_processes);
        db_->insert_events(job.events, hostname_);
        db_->insert_alerts(job.alerts, hostname_);
        return true;
    } catch (const std::exception& e) {
        log::error("database write failed: ", e.what());
        return false;
    }
}

void Engine::db_writer_loop(std::stop_token st) {
    log::info("database writer started");
    auto last_purge = std::chrono::steady_clock::now() - std::chrono::hours(1);
    auto backoff = std::chrono::seconds(1);

    for (;;) {
        auto job = db_queue_.pop_for(std::chrono::seconds(1));
        if (!job) {
            if (db_queue_.closed()) break;  // closed and drained
            continue;
        }

        // Retry a failed write with exponential backoff until it succeeds or
        // we are shutting down. New frames keep queueing meanwhile (bounded).
        while (!write_job(*job)) {
            if (st.stop_requested() || db_queue_.closed()) {
                log::warn("dropping unsaved frame during shutdown");
                break;
            }
            interruptible_sleep_until(st, std::chrono::steady_clock::now() + backoff);
            backoff = std::min(backoff * 2, std::chrono::seconds(30));
        }
        backoff = std::chrono::seconds(1);

        if (cfg_.retention_days > 0 && std::chrono::steady_clock::now() - last_purge >= std::chrono::hours(1)) {
            last_purge = std::chrono::steady_clock::now();
            try {
                const auto removed = db_->purge_older_than(cfg_.retention_days);
                if (removed > 0) log::info("retention: purged ", removed, " snapshots older than ", cfg_.retention_days, " days");
            } catch (const std::exception& e) {
                log::warn("retention purge failed: ", e.what());
            }
        }
    }
    log::info("database writer stopped");
}

}  // namespace sysmon
