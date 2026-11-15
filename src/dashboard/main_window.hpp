#pragma once

#include <QMainWindow>
#include <memory>

class QLabel;
class QTabWidget;

namespace sysmon {
class Database;
}

namespace sysmon::ui {

class LiveClient;
class LiveView;
class HistoryView;
class ProcessView;
class EventView;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(LiveClient* client, std::shared_ptr<Database> db, QWidget* parent = nullptr);

private:
    std::shared_ptr<Database> db_;
    QTabWidget* tabs_;
    LiveView* live_;
    HistoryView* history_;
    ProcessView* processes_;
    EventView* events_;
    QLabel* liveStatus_;
    QLabel* lastFrame_;
    int unseenCritical_ = 0;
};

}  // namespace sysmon::ui
