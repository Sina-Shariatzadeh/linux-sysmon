#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "core/parsers.hpp"

namespace sysmon {

/// Tails the system authentication log (/var/log/auth.log on Debian/Ubuntu,
/// /var/log/secure on RHEL/Fedora) on a background thread, survives log
/// rotation, and reports each failed authentication through a callback.
/// Only lines written after start() are reported.
class AuthLogMonitor {
public:
    using Callback = std::function<void(const parsers::AuthFailure&)>;

    AuthLogMonitor(std::vector<std::string> candidate_paths, Callback cb,
                   std::chrono::milliseconds poll_interval = std::chrono::milliseconds(1000));
    ~AuthLogMonitor();

    AuthLogMonitor(const AuthLogMonitor&) = delete;
    AuthLogMonitor& operator=(const AuthLogMonitor&) = delete;

    void start();
    void stop();

    /// Path currently being followed (empty if none is readable).
    std::string active_path() const;

    /// Feeds one line through the parser/callback (used by the tail loop and tests).
    void process_line(const std::string& line);

private:
    void run(std::stop_token st);

    std::vector<std::string> paths_;
    Callback cb_;
    std::chrono::milliseconds poll_;
    mutable std::mutex mutex_;
    std::string active_;
    std::jthread thread_;
};

}  // namespace sysmon
