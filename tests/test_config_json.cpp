#include <gtest/gtest.h>

#include <limits>

#include "core/config.hpp"
#include "core/json.hpp"

using namespace sysmon;

TEST(Config, DefaultsAreSane) {
    Config c;
    EXPECT_EQ(c.interval.count(), 1000);
    EXPECT_EQ(c.proc_root, "/proc");
    EXPECT_TRUE(c.db_enabled);
}

TEST(Config, ParsesKeysCommentsAndLists) {
    const auto c = Config::from_string(
        "# comment\n"
        "[engine]\n"
        "interval_ms = 2000\n"
        "worker_threads=8   # trailing comment\n"
        "db_enabled = false\n"
        "db_conninfo = host=db port=5433 dbname=metrics\n"
        "suspicious_names = foo, bar ,baz\n"
        "cpu_alert_pct = 85.5\n"
        "live_port = 9999\n");
    EXPECT_EQ(c.interval.count(), 2000);
    EXPECT_EQ(c.worker_threads, 8);
    EXPECT_FALSE(c.db_enabled);
    EXPECT_EQ(c.db_conninfo, "host=db port=5433 dbname=metrics");
    EXPECT_EQ(c.suspicious_names, (std::vector<std::string>{"foo", "bar", "baz"}));
    EXPECT_DOUBLE_EQ(c.cpu_alert_pct, 85.5);
    EXPECT_EQ(c.live_port, 9999);
}

TEST(Config, RejectsUnknownKeysAndBadValues) {
    EXPECT_THROW(Config::from_string("nope = 1\n"), std::runtime_error);
    EXPECT_THROW(Config::from_string("interval_ms = fast\n"), std::runtime_error);
    EXPECT_THROW(Config::from_string("interval_ms = 10\n"), std::runtime_error);
    EXPECT_THROW(Config::from_string("just a line\n"), std::runtime_error);
}

TEST(Config, ShippedConfigFileParses) {
    EXPECT_NO_THROW(Config::load(std::string(SYSMON_SOURCE_DIR) + "/config/sysmon.conf"));
}

TEST(Json, EscapesSpecialCharacters) {
    EXPECT_EQ(json::escape("a\"b\\c\n\t"), "\"a\\\"b\\\\c\\n\\t\"");
    EXPECT_EQ(json::escape(std::string("\x01", 1)), "\"\\u0001\"");
}

TEST(Json, NumbersAreAlwaysValid) {
    EXPECT_EQ(json::number(1.5), "1.5");
    EXPECT_EQ(json::number(std::numeric_limits<double>::quiet_NaN()), "0");
    EXPECT_EQ(json::number(std::numeric_limits<double>::infinity()), "0");
    EXPECT_EQ(json::timestamp(1700000000.1234), "1700000000.123");
}

TEST(Json, FrameContainsSectionsAndLimitsProcesses) {
    MetricsFrame f;
    f.ts = from_epoch_seconds(1700000000.5);
    f.hostname = "box";
    f.cpu.total_pct = 12.5;
    f.cpu.cores.push_back({0, 12.5, 10, 2.5, 0});
    for (int i = 0; i < 5; ++i) {
        ProcessInfo p;
        p.pid = i + 1;
        p.name = "p" + std::to_string(i);
        p.state = 'S';
        f.processes.processes.push_back(p);
    }
    const auto j = json::to_json(f, 2);
    EXPECT_EQ(j.front(), '{');
    EXPECT_EQ(j.back(), '}');
    EXPECT_NE(j.find("\"type\":\"frame\""), std::string::npos);
    EXPECT_NE(j.find("\"host\":\"box\""), std::string::npos);
    EXPECT_NE(j.find("\"ts\":1700000000.500"), std::string::npos);
    EXPECT_NE(j.find("\"name\":\"p1\""), std::string::npos);
    EXPECT_EQ(j.find("\"name\":\"p2\""), std::string::npos);  // limited to 2
    EXPECT_EQ(j.find('\n'), std::string::npos);                 // single line protocol
}

TEST(Json, EventAndAlert) {
    SecurityEvent e;
    e.severity = Severity::Critical;
    e.category = "brute_force";
    e.message = "x";
    e.pid = 42;
    const auto je = json::to_json(e);
    EXPECT_NE(je.find("\"severity\":\"critical\""), std::string::npos);
    EXPECT_NE(je.find("\"pid\":42"), std::string::npos);

    Alert a;
    a.metric = "cpu";
    a.resolved = true;
    EXPECT_NE(json::to_json(a).find("\"resolved\":true"), std::string::npos);
}
