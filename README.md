# sysmon — Linux System Monitoring & Analytics Platform

A Linux monitoring platform written in C++20. It watches the operating system in real time,
stores metrics in PostgreSQL, detects suspicious activity, and shows live and historical
analytics in a Qt 6 dashboard.

| Component          | Technology                          |
|--------------------|-------------------------------------|
| Main language      | C++20                               |
| Database           | PostgreSQL (16 recommended)         |
| Database library   | libpqxx 7.x                         |
| Linux monitoring   | `/proc`, `/sys`                     |
| Multithreading     | `std::jthread`, custom thread pool  |
| Networking         | Boost.Asio (live JSON stream)       |
| Dashboard          | Qt 6 Widgets + Qt Charts            |
| Build system       | CMake ≥ 3.20                        |
| Testing            | GoogleTest                          |

---

## Architecture

```
                         ┌──────────────────────── Linux kernel ────────────────────────┐
                         │ /proc/stat  /proc/meminfo  /proc/diskstats  /proc/net/*  /proc/<pid>/*  /sys/block │
                         └───────────────────────────────┬──────────────────────────────┘
                                                         │
┌──────────────────────────────── sysmond (C++ monitoring engine) ───────────────────────────────┐
│                                                                                                │
│  control thread ── every interval ──▶ ThreadPool ─┬─ CpuCollector                              │
│        ▲                                          ├─ MemoryCollector                           │
│        │                                          ├─ DiskCollector     (I/O rates + storage)   │
│        │                                          ├─ NetworkCollector  (rates, TCP, ports)     │
│        │                                          └─ ProcessCollector  (per-process CPU/RSS)   │
│        │                                                   │                                   │
│        │                                             MetricsFrame                              │
│        │                                                   │                                   │
│  AuthLogMonitor thread ──▶ queue ──▶ SecurityDetector + AlertManager ──▶ events / alerts       │
│  (tails auth.log/secure)                                   │                                   │
│                              ┌─────────────────────────────┴───────────────┐                   │
│                              ▼                                             ▼                   │
│                 LiveServer (Boost.Asio thread)              BlockingQueue ─▶ DB writer thread   │
│                 NDJSON over TCP :9090                       (bounded, retry w/ backoff)         │
└──────────────────────────────┬─────────────────────────────────────────────┬───────────────────┘
                               │                                             │ libpqxx
                               │                                             ▼
                               │                                   ┌───────────────────┐
                               │                                   │    PostgreSQL     │
                               │                                   │ metrics · procs   │
                               │                                   │ events · alerts   │
                               │                                   └─────────┬─────────┘
                               ▼                                             │ libpqxx
                     ┌──────────────────────── sysmon-dashboard (Qt 6) ──────┴─────────┐
                     │  Live │ History (aggregated charts) │ Processes │ Event log search │
                     └─────────────────────────────────────────────────────────────────┘
```

**Design points**

* **Testable parsing.** Every `/proc` format is parsed by a pure function that takes
  a string (`src/core/parsers.*`). Collectors accept a configurable `proc_root`,
  so the tests run against a fake `/proc` tree.
* **Parallel collection.** Each collector owns its own delta state, so all five run on
  the thread pool at the same time. One failing collector is logged and never stops
  the others.
* **Backpressure.** Database writes run on their own thread behind a bounded queue.
  If PostgreSQL goes down, frames are buffered (default 600, about 10 minutes), the
  oldest are dropped when the buffer is full, and writes are retried with exponential
  backoff. Collection never blocks.
* **Live stream.** The daemon pushes newline-delimited JSON to any TCP client. Slow
  clients have messages dropped instead of stalling the engine. New clients get the
  latest frame immediately.

---

## Features

### 1. System monitoring
| Area      | Source                         | Metrics |
|-----------|--------------------------------|---------|
| CPU       | `/proc/stat`, `/proc/loadavg`  | total + **per-core** usage (user/system/iowait), load averages, context switches/s, uptime |
| Memory    | `/proc/meminfo`                | used/available/cached/buffers, **swap** usage |
| Disk      | `/proc/diskstats`, `/sys/block`, `/proc/mounts` + `statvfs` | per-disk read/write B/s, IOPS, utilisation; per-filesystem storage usage |
| Network   | `/proc/net/dev`, `/proc/net/tcp{,6}` | per-interface RX/TX B/s and packets/s, errors; TCP states; listening ports |
| Processes | `/proc/<pid>/{stat,status,cmdline,exe}` | per-process CPU %, RSS, threads, user, state, command line, executable |

### 2. SQL database (`sql/schema.sql`)
`system_metrics` · `cpu_metrics` · `memory_metrics` · `disk_metrics` · `filesystem_metrics` ·
`network_metrics` · `processes` · `security_events` · `alerts`, plus the views
`v_hourly_system` and `v_event_log`. Child tables reference `system_metrics(id)` with
`ON DELETE CASCADE`, so the retention purge deletes whole frames at once. Security events
have a generated `tsvector` column with a GIN index for search.

### 3. Security monitoring
| Detection | How |
|-----------|-----|
| Unusual CPU usage | Z-score against an exponentially weighted baseline (with warm-up and a minimum absolute level) |
| Suspicious processes | Known miner/attack tool names, binaries running from `/tmp`, `/dev/shm`, `/var/tmp`, deleted executables, sustained CPU hogs |
| Failed logins | Tails `/var/log/auth.log` or `/var/log/secure` (survives log rotation). Parses sshd, sudo/PAM and su failures |
| Brute force | N failures from one IP (or local user) inside a sliding window |
| Unusual network activity | RX/TX throughput spikes, spikes in established TCP connections, new listening ports |
| Threshold alerts | CPU, memory, swap and per-filesystem usage, with a sustain count, cooldown and a "resolved" notification |

### 4. Analytics dashboard
* **Live**: headline cards, rolling CPU/memory/swap, network and disk charts, per-core bars, storage table.
* **History**: any stored metric over 15 min to 30 days. Shows average and peak per time bucket, plus a period summary.
* **Processes**: live top-N table you can filter and sort, plus historical per-process statistics (average/peak CPU and memory).
* **Events**: searchable log of security events and alerts, filtered by text, severity and time range. New events appear live, and critical ones put a badge on the tab.

---

## Building

### Dependencies (Ubuntu 24.04 / Debian 12)
```bash
sudo apt install build-essential cmake ninja-build pkg-config \
    libpqxx-dev libboost-dev libgtest-dev \
    qt6-base-dev qt6-charts-dev libgl1-mesa-dev
```
Fedora: `sudo dnf install gcc-c++ cmake ninja-build libpqxx-devel boost-devel gtest-devel qt6-qtbase-devel qt6-qtcharts-devel`

A C++20 compiler is required (GCC ≥ 11 or Clang ≥ 14).

### Build & test
```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

CMake options:

| Option | Default | Effect |
|--------|---------|--------|
| `SYSMON_BUILD_DAEMON`    | ON | build `sysmond` (needs libpqxx, Boost) |
| `SYSMON_BUILD_DASHBOARD` | ON | build `sysmon-dashboard` (needs Qt 6, libpqxx) |
| `SYSMON_BUILD_TESTS`     | ON | build unit tests (GoogleTest is downloaded if not installed) |

To build and test only the core library: `cmake -B build -DSYSMON_BUILD_DAEMON=OFF -DSYSMON_BUILD_DASHBOARD=OFF`

---

## Running

### 1. Start PostgreSQL
```bash
docker compose up -d          # creates db/user "sysmon" and applies sql/schema.sql
```
Or with an existing server:
```bash
sudo -u postgres psql -c "CREATE USER sysmon PASSWORD 'sysmon';" -c "CREATE DATABASE sysmon OWNER sysmon;"
./build/src/sysmond --init-db sql/schema.sql
```

### 2. Start the daemon
```bash
./build/src/sysmond --once --no-db          # quick check: print one JSON frame
sudo ./build/src/sysmond -c config/sysmon.conf
```
Root (or membership in `adm`) is needed to read the auth log and other users'
`/proc/<pid>/exe`. Without it, sysmond still runs, but those detections see less.

Watch the raw live stream:
```bash
nc 127.0.0.1 9090 | head -c 2000
```

### 3. Start the dashboard
```bash
./build/src/dashboard/sysmon-dashboard --host 127.0.0.1 --port 9090 \
    --db "host=localhost dbname=sysmon user=sysmon password=sysmon"
```

### Install as a service
```bash
sudo cmake --install build              # binaries, /usr/local/etc/sysmon/sysmon.conf, schema
sudo mkdir -p /etc/sysmon && sudo cp config/sysmon.conf /etc/sysmon/
sudo cp packaging/sysmond.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sysmond
journalctl -u sysmond -f
```

### Try the detections
```bash
# brute force: 5 failed ssh logins within 5 minutes
for i in $(seq 6); do ssh -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 nosuchuser@localhost; done
# new listening port
python3 -m http.server 8765
# process running from /tmp
cp /bin/sleep /tmp/sleep && /tmp/sleep 60
# CPU anomaly + threshold alert
stress-ng --cpu 0 --timeout 60s
```

---

## Configuration
See [`config/sysmon.conf`](config/sysmon.conf) for every key and its default value. Some important ones:

| Key | Default | Meaning |
|-----|---------|---------|
| `interval_ms` | 1000 | collection period |
| `worker_threads` | 4 | thread pool size |
| `db_conninfo` | `host=localhost …` | libpq connection string |
| `retention_days` | 30 | data older than this is purged hourly |
| `process_store_every` / `process_top_n` | 5 / 25 | store the top 25 processes every 5th frame |
| `live_bind` / `live_port` | 127.0.0.1 / 9090 | live stream endpoint (the stream is unauthenticated: keep it on loopback or put it behind a tunnel) |
| `failed_login_threshold` / `failed_login_window_s` | 5 / 300 | brute-force rule |
| `anomaly_zscore` / `anomaly_warmup_samples` | 3.5 / 30 | anomaly sensitivity |

---

## Example analytics queries
```sql
-- hourly CPU / memory profile for the last day
SELECT * FROM v_hourly_system WHERE hour > now() - interval '1 day' ORDER BY hour;

-- busiest processes this week
SELECT name, avg(cpu_pct) AS avg_cpu, max(rss_kb)/1024 AS peak_mb
FROM processes WHERE ts > now() - interval '7 days'
GROUP BY name ORDER BY avg_cpu DESC LIMIT 10;

-- top attacking IPs
SELECT details->>'ip' AS ip, count(*) FROM security_events
WHERE category = 'failed_login' GROUP BY 1 ORDER BY 2 DESC LIMIT 10;

-- full-text event search
SELECT ts, severity, message FROM security_events
WHERE search @@ plainto_tsquery('simple', 'brute force') ORDER BY ts DESC;
```

---

## Project layout
```
├── CMakeLists.txt
├── config/sysmon.conf           runtime configuration
├── sql/schema.sql               PostgreSQL schema (tables, indexes, views)
├── docker-compose.yml           local PostgreSQL
├── packaging/sysmond.service    systemd unit
├── src/
│   ├── core/                    types, config, /proc parsers, JSON, thread pool, queue, logging
│   ├── collectors/              cpu, memory, disk, network, process collectors
│   ├── security/                anomaly detector, alert manager, auth log monitor
│   ├── db/                      libpqxx persistence + analytics queries
│   ├── daemon/                  engine, Boost.Asio live server, main()
│   └── dashboard/               Qt 6 application
└── tests/                       GoogleTest suites (parsers, collectors, thread pool, security, config/JSON)
```

## Development roadmap
| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | Linux monitoring with C++ (`/proc`, `/sys` collectors) | ✅ |
| 2 | PostgreSQL integration (schema, libpqxx writer) | ✅ |
| 3 | Multithreaded collection engine (thread pool, async DB writer) | ✅ |
| 4 | Historical analytics (bucketed queries, process stats, event search) | ✅ |
| 5 | Qt dashboard (live, history, processes, events) | ✅ |
| 6 | Security detection and alerting | ✅ |

Ideas for further work: TLS and authentication on the live stream, monitoring several
hosts from one dashboard, TimescaleDB hypertables, reading journald directly with
`sd_journal`, and e-mail or webhook notifications for critical events.
