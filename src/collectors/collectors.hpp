#pragma once
// Collectors read /proc and /sys and turn raw counters into rates.
// Each collector keeps the previous sample it needs for deltas, so a single
// instance must not be sampled from two threads at once. The engine samples
// *different* collectors in parallel on its thread pool.

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

#include "core/parsers.hpp"
#include "core/types.hpp"

namespace sysmon {

using SteadyClock = std::chrono::steady_clock;

class CpuCollector {
public:
    explicit CpuCollector(std::string proc_root = "/proc");
    CpuSnapshot sample();

private:
    std::string root_;
    parsers::ProcStat prev_;
    SteadyClock::time_point prev_time_;
};

class MemoryCollector {
public:
    explicit MemoryCollector(std::string proc_root = "/proc");
    MemorySnapshot sample() const;

private:
    std::string root_;
};

class DiskCollector {
public:
    DiskCollector(std::string proc_root = "/proc", std::string sys_root = "/sys");
    DiskSnapshot sample();

private:
    bool is_physical_disk(const std::string& device) const;
    std::vector<FilesystemUsage> filesystems() const;

    std::string proc_root_, sys_root_;
    std::map<std::string, DiskCounters> prev_;
    SteadyClock::time_point prev_time_;
};

class NetworkCollector {
public:
    NetworkCollector(std::string proc_root = "/proc", bool include_loopback = false);
    NetworkSnapshot sample();

private:
    std::string root_;
    bool include_loopback_;
    std::map<std::string, NetCounters> prev_;
    SteadyClock::time_point prev_time_;
};

class ProcessCollector {
public:
    explicit ProcessCollector(std::string proc_root = "/proc");
    ProcessSnapshot sample();

private:
    struct Prev {
        uint64_t ticks = 0;
        uint64_t start = 0;
    };
    std::string username(uint32_t uid);

    std::string root_;
    long clk_tck_;
    long page_kb_;
    uint64_t btime_ = 0;
    std::unordered_map<int, Prev> prev_;
    std::unordered_map<uint32_t, std::string> users_;
    SteadyClock::time_point prev_time_;
};

}  // namespace sysmon
