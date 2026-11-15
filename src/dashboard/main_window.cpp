#include "main_window.hpp"

#include <QAction>
#include <QApplication>
#include <QDateTime>
#include <QJsonObject>
#include <QLabel>
#include <QMenuBar>
#include <QMessageBox>
#include <QStatusBar>
#include <QTabWidget>

#include "event_view.hpp"
#include "history_view.hpp"
#include "live_client.hpp"
#include "live_view.hpp"
#include "process_view.hpp"

namespace sysmon::ui {

MainWindow::MainWindow(LiveClient* client, std::shared_ptr<Database> db, QWidget* parent)
    : QMainWindow(parent),
      db_(std::move(db)),
      tabs_(new QTabWidget),
      live_(new LiveView),
      history_(new HistoryView(db_)),
      processes_(new ProcessView(db_)),
      events_(new EventView(db_)),
      liveStatus_(new QLabel),
      lastFrame_(new QLabel) {
    setWindowTitle("sysmon — Linux System Monitoring & Analytics");
    resize(1400, 900);

    tabs_->addTab(live_, "Live");
    tabs_->addTab(history_, "History");
    tabs_->addTab(processes_, "Processes");
    tabs_->addTab(events_, "Events");
    setCentralWidget(tabs_);

    statusBar()->addWidget(liveStatus_, 1);
    statusBar()->addPermanentWidget(lastFrame_);

    // Actions are created explicitly: QMenu::addAction overloads changed between Qt 6.2 and 6.3.
    auto* file = menuBar()->addMenu("&File");
    auto* refreshAct = file->addAction("&Refresh analytics");
    refreshAct->setShortcut(QKeySequence::Refresh);
    connect(refreshAct, &QAction::triggered, this, [this] {
        history_->refresh();
        processes_->refreshStats();
        events_->search();
    });
    file->addSeparator();
    auto* quitAct = file->addAction("&Quit");
    quitAct->setShortcut(QKeySequence::Quit);
    connect(quitAct, &QAction::triggered, qApp, &QApplication::quit);
    auto* help = menuBar()->addMenu("&Help");
    auto* aboutAct = help->addAction("&About");
    connect(aboutAct, &QAction::triggered, this, [this] {
        QMessageBox::about(this, "About sysmon",
                           "<h3>sysmon dashboard</h3>"
                           "<p>Real-time and historical analytics for Linux hosts.</p>"
                           "<p>Live data: sysmond TCP stream (Boost.Asio).<br>"
                           "History: PostgreSQL via libpqxx.</p>");
    });

    connect(client, &LiveClient::connectionChanged, this, [this](bool connected, const QString& msg) {
        liveStatus_->setText(msg);
        liveStatus_->setStyleSheet(connected ? "color: #2a2;" : "color: #c60;");
    });
    connect(client, &LiveClient::frameReceived, live_, &LiveView::updateFrame);
    connect(client, &LiveClient::frameReceived, processes_, &ProcessView::updateFrame);
    connect(client, &LiveClient::frameReceived, this, [this](const QJsonObject& f) {
        lastFrame_->setText(QString("%1 · frame #%2 · %3")
                                .arg(f["host"].toString())
                                .arg(f["seq"].toVariant().toLongLong())
                                .arg(QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(f["ts"].toDouble() * 1000))
                                         .toString("HH:mm:ss")));
    });
    connect(client, &LiveClient::eventReceived, events_, &EventView::addLiveEvent);

    // Badge the Events tab when critical events arrive while it is hidden.
    connect(events_, &EventView::criticalEventReceived, this, [this](const QString& msg) {
        statusBar()->showMessage("CRITICAL: " + msg, 15000);
        if (tabs_->currentWidget() != events_) tabs_->setTabText(3, QString("Events (%1)").arg(++unseenCritical_));
    });
    connect(tabs_, &QTabWidget::currentChanged, this, [this](int idx) {
        if (tabs_->widget(idx) == events_) {
            unseenCritical_ = 0;
            tabs_->setTabText(3, "Events");
        }
    });

    // Load the database-backed tabs once the window is up.
    QMetaObject::invokeMethod(this, [this] {
        history_->refresh();
        events_->search();
    }, Qt::QueuedConnection);
}

}  // namespace sysmon::ui
