#include "history_view.hpp"

#include <QApplication>
#include <QChart>
#include <QChartView>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDateTimeAxis>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineSeries>
#include <QPainter>
#include <QPushButton>
#include <QTimer>
#include <QValueAxis>
#include <QVBoxLayout>
#include <algorithm>

#include "db/database.hpp"
#include "widgets.hpp"

namespace sysmon::ui {
namespace {

bool isByteRate(HistoryMetric m) {
    return m == HistoryMetric::NetRx || m == HistoryMetric::NetTx || m == HistoryMetric::DiskRead ||
           m == HistoryMetric::DiskWrite;
}

bool isPercent(HistoryMetric m) {
    return m == HistoryMetric::CpuTotal || m == HistoryMetric::MemoryUsed || m == HistoryMetric::SwapUsed;
}

}  // namespace

HistoryView::HistoryView(std::shared_ptr<Database> db, QWidget* parent)
    : QWidget(parent),
      db_(std::move(db)),
      metricCombo_(new QComboBox),
      rangeCombo_(new RangeCombo),
      autoRefresh_(new QCheckBox("Auto-refresh (30 s)")),
      timer_(new QTimer(this)),
      chartView_(new QChartView),
      summary_(new QLabel) {
    for (auto m : {HistoryMetric::CpuTotal, HistoryMetric::MemoryUsed, HistoryMetric::SwapUsed, HistoryMetric::Load1,
                   HistoryMetric::NetRx, HistoryMetric::NetTx, HistoryMetric::DiskRead, HistoryMetric::DiskWrite,
                   HistoryMetric::ProcessCount, HistoryMetric::TcpEstablished})
        metricCombo_->addItem(to_label(m), static_cast<int>(m));

    auto* refreshBtn = new QPushButton("Refresh");
    auto* controls = new QHBoxLayout;
    controls->addWidget(new QLabel("Metric:"));
    controls->addWidget(metricCombo_);
    controls->addWidget(new QLabel("Range:"));
    controls->addWidget(rangeCombo_);
    controls->addWidget(refreshBtn);
    controls->addWidget(autoRefresh_);
    controls->addStretch();

    summary_->setTextFormat(Qt::RichText);
    summary_->setWordWrap(true);
    chartView_->setRenderHint(QPainter::Antialiasing);
    chartView_->setChart(new QChart);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(controls);
    layout->addWidget(chartView_, 1);
    layout->addWidget(summary_);

    connect(refreshBtn, &QPushButton::clicked, this, &HistoryView::refresh);
    connect(metricCombo_, &QComboBox::currentIndexChanged, this, &HistoryView::refresh);
    connect(rangeCombo_, &QComboBox::currentIndexChanged, this, &HistoryView::refresh);
    timer_->setInterval(30000);
    connect(timer_, &QTimer::timeout, this, &HistoryView::refresh);
    connect(autoRefresh_, &QCheckBox::toggled, this, [this](bool on) { on ? timer_->start() : timer_->stop(); });
}

void HistoryView::refresh() {
    const auto metric = static_cast<HistoryMetric>(metricCombo_->currentData().toInt());
    const auto range = rangeCombo_->range();
    const auto to = Clock::now();
    const auto from = to - range;
    const int bucket = std::max<int>(1, static_cast<int>(range.count() / 300));  // ~300 points

    QApplication::setOverrideCursor(Qt::WaitCursor);
    std::vector<SeriesPoint> points;
    PeriodSummary sum;
    QString error;
    try {
        points = db_->metric_history(metric, from, to, bucket);
        sum = db_->summary(from, to);
    } catch (const std::exception& e) {
        error = QString::fromUtf8(e.what());
    }
    QApplication::restoreOverrideCursor();

    if (!error.isEmpty()) {
        summary_->setText("<span style='color:#d33'><b>Database error:</b> " + error.toHtmlEscaped() + "</span>");
        return;
    }

    const double scale = isByteRate(metric) ? 1.0 / 1024.0 : 1.0;
    auto* avg = new QLineSeries;
    auto* max = new QLineSeries;
    avg->setName("Average");
    max->setName("Peak");
    double maxY = 0;
    for (const auto& p : points) {
        const double ms = p.ts * 1000.0;
        avg->append(ms, p.avg * scale);
        max->append(ms, p.max * scale);
        maxY = std::max(maxY, p.max * scale);
    }

    auto* chart = new QChart;
    chart->setTitle(QString("%1 — %2 (bucket %3 s, %4 points)")
                        .arg(QString::fromUtf8(to_label(metric)), rangeCombo_->currentText())
                        .arg(bucket)
                        .arg(points.size()));
    chart->addSeries(max);
    chart->addSeries(avg);
    chart->legend()->setAlignment(Qt::AlignBottom);

    auto* axisX = new QDateTimeAxis;
    axisX->setFormat(range.count() > 2 * 86400 ? "MM-dd HH:mm" : "HH:mm");
    axisX->setTickCount(8);
    axisX->setRange(QDateTime::fromSecsSinceEpoch(static_cast<qint64>(to_epoch_seconds(from))),
                    QDateTime::fromSecsSinceEpoch(static_cast<qint64>(to_epoch_seconds(to))));
    auto* axisY = new QValueAxis;
    axisY->setRange(0, isPercent(metric) ? 100.0 : std::max(1.0, maxY * 1.15));
    axisY->setTitleText(isByteRate(metric) ? "KiB/s" : isPercent(metric) ? "%" : "");
    chart->addAxis(axisX, Qt::AlignBottom);
    chart->addAxis(axisY, Qt::AlignLeft);
    for (auto* s : {max, avg}) {
        s->attachAxis(axisX);
        s->attachAxis(axisY);
    }

    QChart* old = chartView_->chart();
    chartView_->setChart(chart);
    delete old;

    summary_->setText(QString("<b>Period summary</b> — samples: %1 &nbsp;|&nbsp; CPU avg %2&#37; / peak %3&#37; "
                              "&nbsp;|&nbsp; Memory avg %4&#37; / peak %5&#37; &nbsp;|&nbsp; Load avg %6 "
                              "&nbsp;|&nbsp; Security events: %7 (<span style='color:#d33'>%8 critical</span>) "
                              "&nbsp;|&nbsp; Alerts: %9")
                          .arg(sum.samples)
                          .arg(sum.avg_cpu, 0, 'f', 1)
                          .arg(sum.max_cpu, 0, 'f', 1)
                          .arg(sum.avg_mem, 0, 'f', 1)
                          .arg(sum.max_mem, 0, 'f', 1)
                          .arg(sum.avg_load1, 0, 'f', 2)
                          .arg(sum.security_events)
                          .arg(sum.critical_events)
                          .arg(sum.alerts));
}

}  // namespace sysmon::ui
