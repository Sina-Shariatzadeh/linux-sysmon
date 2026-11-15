#include "widgets.hpp"

#include <QChart>
#include <QPainter>
#include <QVBoxLayout>
#include <algorithm>

namespace sysmon::ui {

// ----------------------------------------------------------- RollingChart --
RollingChart::RollingChart(const QString& title, const QStringList& seriesNames, const QString& unit,
                           bool fixedPercent, int window, QWidget* parent)
    : QChartView(parent), axisX_(new QValueAxis), axisY_(new QValueAxis), window_(window), fixedPercent_(fixedPercent) {
    auto* chart = new QChart;
    chart->setTitle(title);
    chart->legend()->setAlignment(Qt::AlignBottom);
    chart->setMargins(QMargins(4, 4, 4, 4));

    axisX_->setRange(0, window_);
    axisX_->setLabelsVisible(false);
    axisX_->setTickCount(7);
    axisX_->setTitleText(QString("last %1 samples").arg(window_));
    axisY_->setRange(0, fixedPercent_ ? 100 : 1);
    axisY_->setTitleText(unit);
    axisY_->setLabelFormat(fixedPercent_ ? "%d" : "%.1f");
    chart->addAxis(axisX_, Qt::AlignBottom);
    chart->addAxis(axisY_, Qt::AlignLeft);

    for (const auto& name : seriesNames) {
        auto* s = new QLineSeries;
        s->setName(name);
        chart->addSeries(s);
        s->attachAxis(axisX_);
        s->attachAxis(axisY_);
        series_.append(s);
    }
    setChart(chart);
    setRenderHint(QPainter::Antialiasing);
    setMinimumHeight(200);
}

void RollingChart::append(const QList<double>& values) {
    ++x_;
    double maxY = 0;
    for (int i = 0; i < series_.size() && i < values.size(); ++i) {
        auto* s = series_[i];
        s->append(static_cast<double>(x_), values[i]);
        if (s->count() > window_ + 1) s->removePoints(0, s->count() - window_ - 1);
        for (const auto& p : s->points()) maxY = std::max(maxY, p.y());
    }
    axisX_->setRange(static_cast<double>(x_ - window_), static_cast<double>(x_));
    if (!fixedPercent_) axisY_->setRange(0, std::max(1.0, maxY * 1.2));
}

// ------------------------------------------------------------- RangeCombo --
RangeCombo::RangeCombo(QWidget* parent, int defaultIndex) : QComboBox(parent) {
    addItem("Last 15 minutes", 15 * 60);
    addItem("Last hour", 3600);
    addItem("Last 6 hours", 6 * 3600);
    addItem("Last 24 hours", 24 * 3600);
    addItem("Last 7 days", 7 * 24 * 3600);
    addItem("Last 30 days", 30 * 24 * 3600);
    setCurrentIndex(defaultIndex);
}

std::chrono::seconds RangeCombo::range() const { return std::chrono::seconds(currentData().toLongLong()); }

// --------------------------------------------------------------- StatCard --
StatCard::StatCard(const QString& title, QWidget* parent) : QFrame(parent), value_(new QLabel("–")), sub_(new QLabel) {
    setFrameShape(QFrame::StyledPanel);
    auto* layout = new QVBoxLayout(this);
    auto* t = new QLabel(title);
    t->setStyleSheet("color: palette(mid); font-size: 11px; text-transform: uppercase;");
    value_->setStyleSheet("font-size: 22px; font-weight: 600;");
    sub_->setStyleSheet("color: palette(mid); font-size: 11px;");
    layout->addWidget(t);
    layout->addWidget(value_);
    layout->addWidget(sub_);
    setMinimumWidth(130);
}

void StatCard::setValue(const QString& value, const QString& sub) {
    value_->setText(value);
    sub_->setText(sub);
}

}  // namespace sysmon::ui
