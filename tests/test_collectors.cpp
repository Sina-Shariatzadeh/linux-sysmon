// Collector tests against a fake /proc + /sys tree written to a temp dir,
// so they are deterministic and do not depend on the build machine.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <random>
#include <thread>

#include "collectors/collectors.hpp"

using namespace sysmon;
namespace fs = std::filesystem;

namespace {

class FakeProc : public ::testing::Test {
protected:
    void SetUp() override {
        std::random_device rd;
        root_ = fs::temp_directory_path() / ("sysmon_test_" + std::to_string(rd()));
        fs::create_directories(proc() / "net");
        fs::create_directories(sys() / "block" / "sda");
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    fs::path proc() const { return root_ / "proc"; }
    fs::path sys() const { return root_ / "sys"; }

    void write(const fs::path& p, const std::string& content) {
        fs::create_directories(p.parent_path());
        std::ofstream(p, std::ios::binary | std::ios::trunc) << content;
    }

    fs::path root_;
};

}  // namespace

TEST_F(FakeProc, CpuCollectorComputesTotalAndPerCore) {
    write(proc() / "stat", "cpu  100 0 100 800 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0\nctxt 1000\n");
    write(proc() / "loadavg", "1.50 1.00 0.50 1/100 999\n");
    write(proc() / "uptime", "3600.00 7000.00\n");
    CpuCollector cpu(proc().string());

    // cpu0 fully busy, cpu1 fully idle during the interval.
    write(proc() / "stat", "cpu  200 0 100 900 0 0 0 0\ncpu0 150 0 50 400 0 0 0 0\ncpu1 50 0 50 500 0 0 0 0\nctxt 2000\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    const auto s = cpu.sample();

    EXPECT_DOUBLE_EQ(s.total_pct, 50.0);
    ASSERT_EQ(s.cores.size(), 2u);
    EXPECT_DOUBLE_EQ(s.cores[0].usage_pct, 100.0);
    EXPECT_DOUBLE_EQ(s.cores[1].usage_pct, 0.0);
    EXPECT_DOUBLE_EQ(s.load1, 1.5);
    EXPECT_DOUBLE_EQ(s.uptime_s, 3600.0);
    EXPECT_GT(s.ctx_switches_per_s, 0.0);
}

TEST_F(FakeProc, MemoryCollectorReadsMeminfo) {
    write(proc() / "meminfo", "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n");
    const auto m = MemoryCollector(proc().string()).sample();
    EXPECT_DOUBLE_EQ(m.used_pct, 75.0);
}

TEST_F(FakeProc, MissingFilesYieldEmptySnapshots) {
    EXPECT_EQ(MemoryCollector(proc().string()).sample().total_kb, 0u);
    NetworkCollector net(proc().string());
    EXPECT_TRUE(net.sample().interfaces.empty());
}

TEST_F(FakeProc, DiskCollectorFiltersDevicesAndComputesRates) {
    write(proc() / "diskstats",
          "8 0 sda 100 0 1000 0 100 0 1000 0 0 100 0\n"
          "8 1 sda1 100 0 1000 0 100 0 1000 0 0 100 0\n"
          "7 0 loop0 100 0 1000 0 100 0 1000 0 0 100 0\n");
    DiskCollector disk(proc().string(), sys().string());
    write(proc() / "diskstats",
          "8 0 sda 200 0 3000 0 150 0 2000 0 0 150 0\n"
          "8 1 sda1 200 0 3000 0 150 0 2000 0 0 150 0\n"
          "7 0 loop0 200 0 3000 0 150 0 2000 0 0 150 0\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const auto s = disk.sample();

    ASSERT_EQ(s.io.size(), 1u);  // partition and loop device excluded
    EXPECT_EQ(s.io[0].device, "sda");
    EXPECT_GT(s.io[0].read_bps, 0.0);
    EXPECT_GT(s.io[0].write_bps, 0.0);
    EXPECT_GT(s.io[0].read_bps, s.io[0].write_bps);  // 2000 vs 1000 sectors
    EXPECT_LE(s.io[0].util_pct, 100.0);
}

TEST_F(FakeProc, NetworkCollectorSkipsLoopbackAndCountsTcp) {
    const std::string hdr = "Inter-| Receive | Transmit\n face |bytes packets|bytes packets\n";
    write(proc() / "net" / "dev", hdr + "lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\neth0: 1000 10 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n");
    write(proc() / "net" / "tcp",
          "sl local rem st\n0: 00000000:0050 00000000:0000 0A x\n1: 0100007F:0050 0200007F:9999 01 x\n");
    NetworkCollector net(proc().string(), false);
    write(proc() / "net" / "dev", hdr + "lo: 9 9 0 0 0 0 0 0 9 9 0 0 0 0 0 0\neth0: 11000 20 0 0 0 0 0 0 1500 15 0 0 0 0 0 0\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const auto s = net.sample();

    ASSERT_EQ(s.interfaces.size(), 1u);
    EXPECT_EQ(s.interfaces[0].iface, "eth0");
    EXPECT_GT(s.total_rx_bps, s.total_tx_bps);
    EXPECT_EQ(s.tcp_listen, 1);
    EXPECT_EQ(s.tcp_established, 1);
    EXPECT_EQ(s.listen_ports, std::vector<uint16_t>{80});
}

TEST_F(FakeProc, ProcessCollectorEnumeratesAndComputesCpu) {
    write(proc() / "stat", "cpu 0 0 0 0 0 0 0 0\nbtime 1700000000\n");
    auto write_pid = [&](uint64_t utime) {
        write(proc() / "42" / "stat", "42 (worker) R 1 42 42 0 -1 0 0 0 0 0 " + std::to_string(utime) +
                                          " 0 0 0 20 0 4 0 1000 104857600 256 0 0\n");
        write(proc() / "42" / "status", "Name:\tworker\nUid:\t0\t0\t0\t0\n");
        write(proc() / "42" / "cmdline", std::string("/usr/bin/worker\0--fast\0", 23));
    };
    write_pid(100);
    write(proc() / "self" / "stat", "not a pid dir");

    ProcessCollector pc(proc().string());
    auto first = pc.sample();
    ASSERT_EQ(first.processes.size(), 1u);
    EXPECT_DOUBLE_EQ(first.processes[0].cpu_pct, 0.0);  // no previous sample yet

    write_pid(200);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const auto s = pc.sample();
    ASSERT_EQ(s.processes.size(), 1u);
    const auto& p = s.processes[0];
    EXPECT_EQ(p.pid, 42);
    EXPECT_EQ(p.name, "worker");
    EXPECT_EQ(p.cmdline, "/usr/bin/worker --fast");
    EXPECT_EQ(p.uid, 0u);
    EXPECT_EQ(p.threads, 4);
    EXPECT_GT(p.cpu_pct, 0.0);
    EXPECT_EQ(s.running, 1);
}
