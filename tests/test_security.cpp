#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>

#include "security/alert_manager.hpp"
#include "security/auth_log_monitor.hpp"
#include "security/rolling_stats.hpp"
#include "security/security_detector.hpp"

using namespace sysmon;
using namespace std::chrono_literals;

namespace {

Config test_config() {
    Config c;
    c.anomaly_warmup_samples = 20;
    c.anomaly_zscore = 3.0;
    c.event_cooldown_s = 60;
    c.alert_sustain_samples = 3;
    c.alert_cooldown_s = 60;
    c.proc_cpu_hog_samples = 3;
    c.failed_login_threshold = 3;
    c.failed_login_window_s = 60;
    return c;
}

MetricsFrame frame(TimePoint ts, double cpu) {
    MetricsFrame f;
    f.ts = ts;
    f.cpu.total_pct = cpu;
    return f;
}

ProcessInfo proc(int pid, std::string name, std::string exe = "", double cpu = 0) {
    ProcessInfo p;
    p.pid = pid;
    p.name = std::move(name);
    p.exe = std::move(exe);
    p.cpu_pct = cpu;
    p.user = "nobody";
    p.start_ticks = static_cast<uint64_t>(pid) * 10;
    return p;
}

bool has_category(const std::vector<SecurityEvent>& ev, const std::string& cat) {
    return std::any_of(ev.begin(), ev.end(), [&](const SecurityEvent& e) { return e.category == cat; });
}

}  // namespace

TEST(RollingStats, TracksMeanAndFlagsOutliers) {
    RollingStats s(0.1, 1.0);
    for (int i = 0; i < 200; ++i) s.update(10.0 + (i % 2));  // 10, 11, 10, 11 ...
    EXPECT_NEAR(s.mean(), 10.5, 0.2);
    EXPECT_LT(s.zscore(11.0), 2.0);
    EXPECT_GT(s.zscore(60.0), 10.0);
}

TEST(SecurityDetector, CpuAnomalyAfterWarmupOnly) {
    SecurityDetector d(test_config());
    auto t = Clock::now();
    // A spike during warm-up is not reported.
    EXPECT_FALSE(has_category(d.analyze(frame(t, 99)), "cpu_anomaly"));
    for (int i = 0; i < 150; ++i) {
        t += 1s;
        EXPECT_FALSE(has_category(d.analyze(frame(t, 10 + (i % 3))), "cpu_anomaly"));
    }
    t += 1s;
    auto ev = d.analyze(frame(t, 97));
    ASSERT_TRUE(has_category(ev, "cpu_anomaly"));
    EXPECT_EQ(ev[0].severity, Severity::Critical);

    // Cooldown suppresses an immediate repeat.
    t += 1s;
    EXPECT_FALSE(has_category(d.analyze(frame(t, 98)), "cpu_anomaly"));
}

TEST(SecurityDetector, FlagsSuspiciousProcessesOnce) {
    SecurityDetector d(test_config());
    auto f = frame(Clock::now(), 5);
    f.processes.processes = {proc(10, "bash", "/usr/bin/bash"), proc(11, "xmrig", "/opt/xmrig"),
                             proc(12, "payload", "/tmp/.x/payload"), proc(13, "svc", "/usr/sbin/svc (deleted)")};
    auto ev = d.analyze(f);
    const auto count = std::count_if(ev.begin(), ev.end(), [](auto& e) { return e.category == "suspicious_process"; });
    EXPECT_EQ(count, 3);
    for (const auto& e : ev) {
        if (e.category != "suspicious_process") continue;
        ASSERT_TRUE(e.pid.has_value());
        EXPECT_NE(*e.pid, 10);
        if (*e.pid == 11 || *e.pid == 12) {
            EXPECT_EQ(e.severity, Severity::Critical);
        }
        if (*e.pid == 13) {
            EXPECT_EQ(e.severity, Severity::Warning);
        }
    }
    // Same processes again: no duplicates.
    f.ts += 1s;
    EXPECT_FALSE(has_category(d.analyze(f), "suspicious_process"));
}

TEST(SecurityDetector, CpuHogNeedsSustainedUsage) {
    SecurityDetector d(test_config());
    auto t = Clock::now();
    auto f = frame(t, 50);
    f.processes.processes = {proc(20, "busy", "/usr/bin/busy", 99)};
    EXPECT_FALSE(has_category(d.analyze(f), "process_cpu_hog"));
    EXPECT_FALSE(has_category(d.analyze(f), "process_cpu_hog"));
    EXPECT_TRUE(has_category(d.analyze(f), "process_cpu_hog"));
    EXPECT_FALSE(has_category(d.analyze(f), "process_cpu_hog"));  // reported once per streak
}

TEST(SecurityDetector, NewListeningPortAfterBaseline) {
    SecurityDetector d(test_config());
    auto f = frame(Clock::now(), 5);
    f.network.listen_ports = {22, 80};
    EXPECT_FALSE(has_category(d.analyze(f), "new_listening_port"));
    f.network.listen_ports = {22, 80, 4444};
    auto ev = d.analyze(f);
    ASSERT_TRUE(has_category(ev, "new_listening_port"));
    EXPECT_NE(ev.back().message.find("4444"), std::string::npos);
    EXPECT_FALSE(has_category(d.analyze(f), "new_listening_port"));
}

TEST(SecurityDetector, NetworkSpike) {
    auto cfg = test_config();
    cfg.net_anomaly_min_bps = 1e6;
    SecurityDetector d(cfg);
    auto t = Clock::now();
    for (int i = 0; i < 40; ++i) {
        auto f = frame(t += 1s, 5);
        f.network.total_rx_bps = 50e3 + (i % 5) * 1e3;
        d.analyze(f);
    }
    auto f = frame(t += 1s, 5);
    f.network.total_rx_bps = 80e6;
    EXPECT_TRUE(has_category(d.analyze(f), "network_anomaly"));
}

TEST(SecurityDetector, BruteForceDetection) {
    SecurityDetector d(test_config());
    parsers::AuthFailure a{"sshd", "root", "203.0.113.9", false};
    auto t = Clock::now();
    EXPECT_FALSE(has_category(d.on_auth_failure(a, t), "brute_force"));
    EXPECT_FALSE(has_category(d.on_auth_failure(a, t + 1s), "brute_force"));
    auto ev = d.on_auth_failure(a, t + 2s);
    EXPECT_TRUE(has_category(ev, "failed_login"));
    ASSERT_TRUE(has_category(ev, "brute_force"));
    EXPECT_EQ(ev.back().severity, Severity::Critical);

    // A different source is tracked separately.
    parsers::AuthFailure other{"sshd", "root", "198.51.100.1", false};
    EXPECT_FALSE(has_category(d.on_auth_failure(other, t + 3s), "brute_force"));
}

TEST(SecurityDetector, BruteForceWindowExpires) {
    SecurityDetector d(test_config());
    parsers::AuthFailure a{"sshd", "root", "203.0.113.9", false};
    auto t = Clock::now();
    d.on_auth_failure(a, t);
    d.on_auth_failure(a, t + 1s);
    // Third failure arrives after the 60 s window: only 1-2 failures remain in window.
    EXPECT_FALSE(has_category(d.on_auth_failure(a, t + 120s), "brute_force"));
}

TEST(AlertManager, FiresAfterSustainAndResolves) {
    AlertManager am(test_config());
    auto t = Clock::now();
    auto f = frame(t, 95);
    f.memory.used_pct = 10;
    EXPECT_TRUE(am.evaluate(f).empty());
    f.ts += 1s;
    EXPECT_TRUE(am.evaluate(f).empty());
    f.ts += 1s;
    auto alerts = am.evaluate(f);
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].metric, "cpu");
    EXPECT_EQ(alerts[0].severity, Severity::Critical);  // 95 >= 90 + (100-90)/2
    EXPECT_FALSE(alerts[0].resolved);

    f.ts += 1s;
    EXPECT_TRUE(am.evaluate(f).empty());  // still active, no repeat

    f.ts += 1s;
    f.cpu.total_pct = 20;
    alerts = am.evaluate(f);
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_TRUE(alerts[0].resolved);
    EXPECT_EQ(alerts[0].severity, Severity::Info);
}

TEST(AlertManager, DiskAlertPerFilesystem) {
    AlertManager am(test_config());
    auto f = frame(Clock::now(), 1);
    FilesystemUsage root;
    root.mount_point = "/";
    root.used_pct = 92;
    FilesystemUsage home;
    home.mount_point = "/home";
    home.used_pct = 40;
    f.disk.filesystems = {root, home};
    std::vector<Alert> alerts;
    for (int i = 0; i < 3; ++i) {
        alerts = am.evaluate(f);
        f.ts += 1s;
    }
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].metric, "disk:/");
    EXPECT_EQ(alerts[0].severity, Severity::Warning);
}

TEST(AuthLogMonitor, ProcessLineInvokesCallbackForFailuresOnly) {
    std::vector<parsers::AuthFailure> got;
    AuthLogMonitor m({}, [&](const parsers::AuthFailure& a) { got.push_back(a); });
    m.process_line("host sshd[1]: Failed password for bob from 10.1.1.1 port 2 ssh2");
    m.process_line("host sshd[1]: Accepted password for bob from 10.1.1.1 port 2 ssh2");
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].ip, "10.1.1.1");
}
