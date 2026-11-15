#include <gtest/gtest.h>

#include "core/parsers.hpp"

using namespace sysmon;
using namespace sysmon::parsers;

TEST(ProcStat, ParsesAggregateCoresAndCounters) {
    const char* text =
        "cpu  100 5 50 800 20 3 2 0 0 0\n"
        "cpu0 50 2 25 400 10 1 1 0 0 0\n"
        "cpu1 50 3 25 400 10 2 1 0 0 0\n"
        "intr 12345 0 0\n"
        "ctxt 987654\n"
        "btime 1700000000\n"
        "processes 4242\n"
        "procs_running 3\n";
    const auto st = parse_proc_stat(text);
    EXPECT_EQ(st.total.user, 100u);
    EXPECT_EQ(st.total.idle, 800u);
    EXPECT_EQ(st.total.total(), 980u);
    ASSERT_EQ(st.cores.size(), 2u);
    EXPECT_EQ(st.cores[1].nice, 3u);
    EXPECT_EQ(st.ctxt, 987654u);
    EXPECT_EQ(st.btime, 1700000000u);
    EXPECT_EQ(st.procs_running, 3);
}

TEST(ProcStat, ComputesUsageBetweenSamples) {
    CpuTimes a{100, 0, 100, 800, 0, 0, 0, 0};
    CpuTimes b{150, 0, 150, 850, 50, 0, 0, 0};  // +50 user, +50 sys, +50 idle, +50 iowait
    const auto u = compute_core_usage(a, b, 0);
    EXPECT_DOUBLE_EQ(u.usage_pct, 50.0);
    EXPECT_DOUBLE_EQ(u.user_pct, 25.0);
    EXPECT_DOUBLE_EQ(u.system_pct, 25.0);
    EXPECT_DOUBLE_EQ(u.iowait_pct, 25.0);
}

TEST(ProcStat, UsageHandlesNoProgressAndCounterReset) {
    CpuTimes a{100, 0, 100, 800, 0, 0, 0, 0};
    EXPECT_DOUBLE_EQ(compute_core_usage(a, a, 0).usage_pct, 0.0);
    CpuTimes reset{1, 0, 1, 1, 0, 0, 0, 0};
    const auto u = compute_core_usage(a, reset, 0);
    EXPECT_GE(u.usage_pct, 0.0);
    EXPECT_LE(u.usage_pct, 100.0);
}

TEST(LoadAvgUptime, Parse) {
    const auto l = parse_loadavg("0.52 0.58 0.59 2/1234 56789\n");
    EXPECT_DOUBLE_EQ(l.l1, 0.52);
    EXPECT_DOUBLE_EQ(l.l15, 0.59);
    EXPECT_DOUBLE_EQ(parse_uptime("12345.67 54321.00\n"), 12345.67);
}

TEST(MemInfo, ComputesUsedFromAvailable) {
    const char* text =
        "MemTotal:       16000000 kB\n"
        "MemFree:         2000000 kB\n"
        "MemAvailable:    8000000 kB\n"
        "Buffers:          500000 kB\n"
        "Cached:          4000000 kB\n"
        "SwapTotal:       4000000 kB\n"
        "SwapFree:        3000000 kB\n";
    const auto m = parse_meminfo(text);
    EXPECT_EQ(m.total_kb, 16000000u);
    EXPECT_EQ(m.used_kb, 8000000u);
    EXPECT_DOUBLE_EQ(m.used_pct, 50.0);
    EXPECT_EQ(m.swap_used_kb, 1000000u);
    EXPECT_DOUBLE_EQ(m.swap_pct, 25.0);
}

TEST(MemInfo, FallsBackWithoutMemAvailableAndNoSwap) {
    const auto m = parse_meminfo("MemTotal: 1000 kB\nMemFree: 200 kB\nBuffers: 100 kB\nCached: 200 kB\n");
    EXPECT_EQ(m.available_kb, 500u);
    EXPECT_DOUBLE_EQ(m.used_pct, 50.0);
    EXPECT_DOUBLE_EQ(m.swap_pct, 0.0);
}

TEST(DiskStats, ParsesFields) {
    const char* text =
        "   8       0 sda 1000 10 20000 500 2000 20 40000 900 0 1200 1400 0 0 0 0\n"
        "   8       1 sda1 900 10 18000 450 1900 20 38000 850 0 1100 1300\n"
        "   7       0 loop0 1 0 2 0 0 0 0 0 0 0 0\n"
        "short line\n";
    const auto d = parse_diskstats(text);
    ASSERT_EQ(d.size(), 3u);
    EXPECT_EQ(d[0].device, "sda");
    EXPECT_EQ(d[0].reads_completed, 1000u);
    EXPECT_EQ(d[0].sectors_read, 20000u);
    EXPECT_EQ(d[0].writes_completed, 2000u);
    EXPECT_EQ(d[0].sectors_written, 40000u);
    EXPECT_EQ(d[0].io_ms, 1200u);
}

TEST(NetDev, ParsesInterfacesIncludingNoSpaceAfterColon) {
    const char* text =
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n"
        "  eth0:123456789 1000 1 2 0 0 0 0 987654 900 3 4 0 0 0 0\n";
    const auto n = parse_net_dev(text);
    ASSERT_EQ(n.size(), 2u);
    EXPECT_EQ(n[1].iface, "eth0");
    EXPECT_EQ(n[1].rx_bytes, 123456789u);
    EXPECT_EQ(n[1].rx_errs, 1u);
    EXPECT_EQ(n[1].rx_drop, 2u);
    EXPECT_EQ(n[1].tx_bytes, 987654u);
    EXPECT_EQ(n[1].tx_errs, 3u);
}

TEST(NetTcp, CountsStatesAndListenPorts) {
    const char* text =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n"
        "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1\n"
        "   2: 0F02000A:0016 0202000A:D2F0 01 00000000:00000000 00:00000000 00000000     0        0 3 1\n"
        "   3: 0F02000A:0016 0202000A:D2F1 06 00000000:00000000 00:00000000 00000000     0        0 4 1\n";
    TcpSummary s;
    accumulate_proc_net_tcp(text, s);
    EXPECT_EQ(s.total, 4);
    EXPECT_EQ(s.listen, 2);
    EXPECT_EQ(s.established, 1);
    EXPECT_EQ(s.time_wait, 1);
    EXPECT_EQ(s.listen_ports, (std::set<uint16_t>{22, 8080}));
}

TEST(PidStat, HandlesSpacesAndParensInComm) {
    const char* text =
        "4321 (Web Content (x)) S 1200 4321 1200 0 -1 4194560 1000 0 5 0 250 75 0 0 20 0 27 0 123456 "
        "3000000000 51200 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
    const auto s = parse_pid_stat(text);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->pid, 4321);
    EXPECT_EQ(s->comm, "Web Content (x)");
    EXPECT_EQ(s->state, 'S');
    EXPECT_EQ(s->ppid, 1200);
    EXPECT_EQ(s->utime, 250u);
    EXPECT_EQ(s->stime, 75u);
    EXPECT_EQ(s->num_threads, 27);
    EXPECT_EQ(s->starttime, 123456u);
    EXPECT_EQ(s->vsize, 3000000000u);
    EXPECT_EQ(s->rss_pages, 51200);
}

TEST(PidStat, RejectsGarbage) {
    EXPECT_FALSE(parse_pid_stat("").has_value());
    EXPECT_FALSE(parse_pid_stat("12 (x) S 1").has_value());
}

TEST(PidStatus, ReadsRealUid) {
    EXPECT_EQ(parse_status_uid("Name:\tbash\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n"), 1000u);
    EXPECT_FALSE(parse_status_uid("Name:\tbash\n").has_value());
}

TEST(Cmdline, ReplacesNulsAndTruncates) {
    std::string raw("python3\0-m\0http.server\0", 24);
    EXPECT_EQ(normalize_cmdline(raw), "python3 -m http.server");
    EXPECT_EQ(normalize_cmdline(std::string(1000, 'a'), 10).size(), 10u);
}

TEST(Mounts, DecodesEscapedSpaces) {
    const auto m = parse_mounts("/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt/My\\040Disk ntfs3 rw 0 0\n");
    ASSERT_EQ(m.size(), 2u);
    EXPECT_EQ(m[1].mount_point, "/mnt/My Disk");
    EXPECT_EQ(m[1].fs_type, "ntfs3");
}

// --------------------------------------------------------------- auth -----
TEST(AuthLog, SshFailedPassword) {
    const auto a = parse_auth_failure(
        "Nov 15 10:00:01 host sshd[1234]: Failed password for root from 203.0.113.7 port 51515 ssh2");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->service, "sshd");
    EXPECT_EQ(a->user, "root");
    EXPECT_EQ(a->ip, "203.0.113.7");
    EXPECT_FALSE(a->invalid_user);
}

TEST(AuthLog, SshInvalidUser) {
    const auto a = parse_auth_failure(
        "2026-11-15T10:00:01.123+00:00 host sshd[99]: Failed password for invalid user admin from 198.51.100.2 port "
        "4000 ssh2");
    ASSERT_TRUE(a.has_value());
    EXPECT_TRUE(a->invalid_user);
    EXPECT_EQ(a->user, "admin");
    EXPECT_EQ(a->ip, "198.51.100.2");
}

TEST(AuthLog, SudoPamFailure) {
    const auto a = parse_auth_failure(
        "Nov 15 10:00:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 "
        "tty=/dev/pts/0 ruser=bob rhost=  user=bob");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->service, "sudo");
    EXPECT_EQ(a->user, "bob");
    EXPECT_TRUE(a->ip.empty());
}

TEST(AuthLog, IgnoresSshdPamDuplicateAndNormalLines) {
    EXPECT_FALSE(parse_auth_failure("host sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 "
                                    "euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root")
                     .has_value());
    EXPECT_FALSE(parse_auth_failure("host sshd[1]: Accepted publickey for alice from 10.0.0.2 port 22 ssh2").has_value());
    EXPECT_FALSE(parse_auth_failure("host CRON[5]: pam_unix(cron:session): session opened for user root").has_value());
}

TEST(AuthLog, SuFailure) {
    const auto a = parse_auth_failure("Nov 15 10:00:01 host su[777]: FAILED SU (to root) bob on pts/1");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->service, "su");
    EXPECT_EQ(a->user, "root");
}
