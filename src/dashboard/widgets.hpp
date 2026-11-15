#pragma once
// Reusable dashboard widgets: a rolling real-time line chart, a time-range
// selector shared by the analytics tabs, and a small "stat card".

#include <QChartView>
#include <QComboBox>
#include <QFrame>
#include <QLabel>
#include <QLineSeries>
#include <QList>
#include <QStringList>
#include <QValueAxis>
#include <chrono>

namespace sysmon::ui {

/// Line chart that keeps the last `window` samples and scrolls.
class RollingChart : public QChartView {
public:
    RollingChart(const QString& title, const QStringList& seriesNames, const QString& unit, bool fixedPercent,
                 int window = 120, QWidget* parent = nullptr);
    void append(const QList<double>& values);

private:
    QList<QLineSeries*> series_;
    QValueAxis* axisX_;
    QValueAxis* axisY_;
    int window_;
    bool fixedPercent_;
    qint64 x_ = 0;
};

/// Combo box offering standard look-back windows.
class RangeCombo : public QComboBox {
public:
    explicit RangeCombo(QWidget* parent = nullptr, int defaultIndex = 1);
    std::chrono::seconds range() const;
};

/// Titled value tile used on the live overview.
class StatCard : public QFrame {
public:
    explicit StatCard(const QString& title, QWidget* parent = nullptr);
    void setValue(const QString& value, const QString& sub = {});

private:
    QLabel* value_;
    QLabel* sub_;
};

}  // namespace sysmon::ui
