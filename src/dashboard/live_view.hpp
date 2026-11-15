#pragma once

#include <QJsonObject>
#include <QList>
#include <QWidget>

class QGridLayout;
class QProgressBar;
class QTableWidget;

namespace sysmon::ui {

class RollingChart;
class StatCard;

/// "Live" tab: headline numbers, rolling charts, per-core bars, filesystems.
class LiveView : public QWidget {
    Q_OBJECT
public:
    explicit LiveView(QWidget* parent = nullptr);

public slots:
    void updateFrame(const QJsonObject& frame);

private:
    void ensureCoreBars(int count);

    StatCard *cpuCard_, *memCard_, *swapCard_, *loadCard_, *procCard_, *netCard_, *uptimeCard_;
    RollingChart *usageChart_, *netChart_, *diskChart_;
    QGridLayout* coreGrid_;
    QList<QProgressBar*> coreBars_;
    QTableWidget* fsTable_;
};

}  // namespace sysmon::ui
