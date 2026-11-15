// sysmon-dashboard - Qt 6 analytics dashboard for sysmond.
//
//   sysmon-dashboard [--host 127.0.0.1] [--port 9090] [--db "<libpq conninfo>"]
//
// The database connection string can also be given via $SYSMON_DB.

#include <QApplication>
#include <QCommandLineParser>
#include <QProcessEnvironment>
#include <memory>

#include "db/database.hpp"
#include "live_client.hpp"
#include "main_window.hpp"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("sysmon-dashboard");
    QApplication::setApplicationVersion("1.0.0");

    QCommandLineParser parser;
    parser.setApplicationDescription("Real-time and historical Linux system analytics");
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption hostOpt("host", "sysmond live stream host.", "host", "127.0.0.1");
    QCommandLineOption portOpt("port", "sysmond live stream port.", "port", "9090");
    const QString defaultDb = QProcessEnvironment::systemEnvironment().value(
        "SYSMON_DB", "host=localhost port=5432 dbname=sysmon user=sysmon password=sysmon");
    QCommandLineOption dbOpt("db", "PostgreSQL connection string (libpq format).", "conninfo", defaultDb);
    parser.addOptions({hostOpt, portOpt, dbOpt});
    parser.process(app);

    bool ok = false;
    const auto port = parser.value(portOpt).toUShort(&ok);
    if (!ok) qFatal("invalid --port value");

    // Connects lazily on first query; failures are shown inside each tab.
    auto db = std::make_shared<sysmon::Database>(parser.value(dbOpt).toStdString());

    sysmon::ui::LiveClient client(parser.value(hostOpt), port);
    sysmon::ui::MainWindow window(&client, db);
    window.show();
    client.start();

    return app.exec();
}
