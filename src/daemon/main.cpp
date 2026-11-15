// sysmond - Linux system monitoring daemon.
//
//   sysmond [-c config] [--no-db] [--no-live]   run the collection engine
//   sysmond --init-db sql/schema.sql            create/upgrade the schema
//   sysmond --once                              print one JSON frame and exit

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include "core/config.hpp"
#include "core/json.hpp"
#include "core/log.hpp"
#include "daemon/engine.hpp"
#include "daemon/live_server.hpp"
#include "db/database.hpp"

using namespace sysmon;

namespace {

constexpr const char* kDefaultConfig = "/etc/sysmon/sysmon.conf";

void usage(const char* argv0) {
    std::cout << "Usage: " << argv0 << " [options]\n\n"
              << "Options:\n"
              << "  -c, --config FILE     configuration file (default: " << kDefaultConfig << " if present)\n"
              << "      --init-db FILE    apply SQL schema FILE to the configured database and exit\n"
              << "      --once            collect a single frame, print it as JSON and exit\n"
              << "      --no-db           do not store metrics in PostgreSQL\n"
              << "      --no-live         do not start the live TCP stream\n"
              << "  -h, --help            show this help\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::string config_path;
    std::string schema_path;
    bool once = false, no_db = false, no_live = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need_value = [&](const char* opt) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << opt << " requires a value\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "-c" || a == "--config") config_path = need_value("--config");
        else if (a == "--init-db") schema_path = need_value("--init-db");
        else if (a == "--once") once = true;
        else if (a == "--no-db") no_db = true;
        else if (a == "--no-live") no_live = true;
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else { std::cerr << "unknown option: " << a << "\n"; usage(argv[0]); return 2; }
    }

    Config cfg;
    try {
        if (!config_path.empty()) cfg = Config::load(config_path);
        else if (std::filesystem::exists(kDefaultConfig)) cfg = Config::load(kDefaultConfig);
    } catch (const std::exception& e) {
        std::cerr << "configuration error: " << e.what() << "\n";
        return 2;
    }
    if (no_db) cfg.db_enabled = false;
    if (no_live) cfg.live_enabled = false;

    // ---- one-shot modes --------------------------------------------------
    if (!schema_path.empty()) {
        try {
            Database db(cfg.db_conninfo);
            db.apply_schema_file(schema_path);
            std::cout << "schema applied from " << schema_path << "\n";
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "failed to apply schema: " << e.what() << "\n";
            return 1;
        }
    }

    if (once) {
        Engine engine(cfg, nullptr, nullptr);
        (void)engine.collect();  // prime per-process CPU counters
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << json::to_json(engine.collect(), 15) << std::endl;
        return 0;
    }

    // ---- daemon mode -----------------------------------------------------
    // Block termination signals in every thread; the main thread waits for
    // them synchronously with sigwait() and then stops the engine cleanly.
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigs, nullptr);
    signal(SIGPIPE, SIG_IGN);

    std::shared_ptr<Database> db;
    if (cfg.db_enabled) {
        db = std::make_shared<Database>(cfg.db_conninfo);
        if (db->is_connected()) log::info("connected to PostgreSQL");
        else log::warn("PostgreSQL not reachable yet; frames will be buffered and retried");
    } else {
        log::info("database disabled");
    }

    std::unique_ptr<LiveServer> live;
    if (cfg.live_enabled) {
        try {
            live = std::make_unique<LiveServer>(cfg.live_bind, cfg.live_port);
            live->start();
            log::info("live stream listening on ", cfg.live_bind, ":", live->port());
        } catch (const std::exception& e) {
            log::error("cannot start live server on ", cfg.live_bind, ":", cfg.live_port, ": ", e.what());
            return 1;
        }
    }

    Engine engine(cfg, db, live.get());
    std::jthread worker([&engine](std::stop_token st) {
        try {
            engine.run(st);
        } catch (const std::exception& e) {
            log::error("engine terminated: ", e.what());
            ::kill(::getpid(), SIGTERM);  // wake up sigwait() in main
        }
    });

    int sig = 0;
    sigwait(&sigs, &sig);
    log::info("received ", sig == SIGINT ? "SIGINT" : "SIGTERM", ", shutting down");

    worker.request_stop();
    worker.join();
    if (live) live->stop();
    log::info("bye");
    return 0;
}
