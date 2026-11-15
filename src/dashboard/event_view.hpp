#pragma once

#include <QJsonObject>
#include <QWidget>
#include <memory>

class QComboBox;
class QLabel;
class QLineEdit;
class QTableWidget;

namespace sysmon {
class Database;
}

namespace sysmon::ui {

class RangeCombo;

/// "Events" tab: searchable log of security events and threshold alerts.
/// Results come from PostgreSQL; new live events are prepended as they arrive.
class EventView : public QWidget {
    Q_OBJECT
public:
    EventView(std::shared_ptr<Database> db, QWidget* parent = nullptr);

public slots:
    void search();
    void addLiveEvent(const QJsonObject& event);

signals:
    void criticalEventReceived(const QString& message);

private:
    void insertRow(int row, double ts, const QString& kind, const QString& severity, const QString& subject,
                   const QString& message);
    int minSeverity() const;

    std::shared_ptr<Database> db_;
    QLineEdit* query_;
    QComboBox* severity_;
    RangeCombo* range_;
    QTableWidget* table_;
    QLabel* info_;
};

}  // namespace sysmon::ui
