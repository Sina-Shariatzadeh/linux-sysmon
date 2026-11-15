#pragma once

#include <QJsonObject>
#include <QWidget>
#include <memory>

class QLineEdit;
class QTableWidget;
class QLabel;

namespace sysmon {
class Database;
}

namespace sysmon::ui {

class RangeCombo;

/// "Processes" tab: live top-N process table (filterable, sortable) and
/// historical per-process statistics from PostgreSQL.
class ProcessView : public QWidget {
    Q_OBJECT
public:
    ProcessView(std::shared_ptr<Database> db, QWidget* parent = nullptr);

public slots:
    void updateFrame(const QJsonObject& frame);
    void refreshStats();

private:
    void applyFilter();

    std::shared_ptr<Database> db_;
    QLineEdit* filter_;
    QTableWidget* live_;
    QLabel* liveInfo_;
    RangeCombo* statsRange_;
    QTableWidget* stats_;
    QLabel* statsInfo_;
};

}  // namespace sysmon::ui
