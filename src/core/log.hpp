#pragma once
// Tiny thread-safe logger writing timestamped lines to stderr
// (journald captures stderr when running under systemd).

#include <chrono>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string_view>

namespace sysmon::log {

enum class Level { Debug, Info, Warn, Error };

inline std::mutex& mutex() {
    static std::mutex m;
    return m;
}

template <typename... Args>
void write(Level lvl, Args&&... args) {
    static constexpr std::string_view names[] = {"DEBUG", "INFO ", "WARN ", "ERROR"};
    std::ostringstream os;
    (os << ... << std::forward<Args>(args));

    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&t, &tm);
    char ts[32];
    std::strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);

    std::lock_guard lock(mutex());
    std::cerr << ts << ' ' << names[static_cast<int>(lvl)] << ' ' << os.str() << '\n';
}

template <typename... Args> void debug(Args&&... a) { write(Level::Debug, std::forward<Args>(a)...); }
template <typename... Args> void info(Args&&... a) { write(Level::Info, std::forward<Args>(a)...); }
template <typename... Args> void warn(Args&&... a) { write(Level::Warn, std::forward<Args>(a)...); }
template <typename... Args> void error(Args&&... a) { write(Level::Error, std::forward<Args>(a)...); }

}  // namespace sysmon::log
