#pragma once

#include <QWidget>
#include <memory>

class QChartView;
class QComboBox;
class QLabel;
class QCheckBox;
class QTimer;

namespace sysmon {
class Database;
}

namespace sysmon::ui {

class RangeCombo;

/// "History" tab: aggregated time series from PostgreSQL plus a period summary.
class HistoryView : public QWidget {
    Q_OBJECT
public:
    HistoryView(std::shared_ptr<Database> db, QWidget* parent = nullptr);

public slots:
    void refresh();

private:
    std::shared_ptr<Database> db_;
    QComboBox* metricCombo_;
    RangeCombo* rangeCombo_;
    QCheckBox* autoRefresh_;
    QTimer* timer_;
    QChartView* chartView_;
    QLabel* summary_;
};

}  // namespace sysmon::ui
