#include "live_view.hpp"

#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QProgressBar>
#include <QScrollArea>
#include <QTableWidget>
#include <QVBoxLayout>
#include <cmath>

#include "format.hpp"
#include "widgets.hpp"

namespace sysmon::ui {

LiveView::LiveView(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);

    // ---- headline cards ------------------------------------------------
    auto* cards = new QHBoxLayout;
    cpuCard_ = new StatCard("CPU");
    memCard_ = new StatCard("Memory");
    swapCard_ = new StatCard("Swap");
    loadCard_ = new StatCard("Load average");
    procCard_ = new StatCard("Processes");
    netCard_ = new StatCard("Network");
    uptimeCard_ = new StatCard("Uptime");
    for (auto* c : {cpuCard_, memCard_, swapCard_, loadCard_, procCard_, netCard_, uptimeCard_}) cards->addWidget(c);
    root->addLayout(cards);

    // ---- charts --------------------------------------------------------
    auto* charts = new QGridLayout;
    usageChart_ = new RollingChart("CPU & memory", {"CPU %", "Memory %", "Swap %"}, "%", true);
    netChart_ = new RollingChart("Network throughput", {"RX", "TX"}, "KiB/s", false);
    diskChart_ = new RollingChart("Disk I/O", {"Read", "Write"}, "KiB/s", false);
    charts->addWidget(usageChart_, 0, 0, 1, 2);
    charts->addWidget(netChart_, 1, 0);
    charts->addWidget(diskChart_, 1, 1);
    root->addLayout(charts, 3);

    // ---- per-core bars + filesystems ----------------------------------
    auto* bottom = new QHBoxLayout;
    auto* coreBox = new QGroupBox("CPU cores");
    coreGrid_ = new QGridLayout;
    auto* coreHolder = new QWidget;
    coreHolder->setLayout(coreGrid_);
    auto* coreScroll = new QScrollArea;
    coreScroll->setWidgetResizable(true);
    coreScroll->setWidget(coreHolder);
    coreScroll->setFrameShape(QFrame::NoFrame);
    auto* coreLayout = new QVBoxLayout(coreBox);
    coreLayout->addWidget(coreScroll);
    bottom->addWidget(coreBox, 1);

    auto* fsBox = new QGroupBox("Storage");
    fsTable_ = new QTableWidget(0, 5);
    fsTable_->setHorizontalHeaderLabels({"Mount", "Device", "Type", "Used", "Size"});
    fsTable_->horizontalHeader()->setStretchLastSection(true);
    fsTable_->verticalHeader()->setVisible(false);
    fsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fsTable_->setSelectionMode(QAbstractItemView::NoSelection);
    auto* fsLayout = new QVBoxLayout(fsBox);
    fsLayout->addWidget(fsTable_);
    bottom->addWidget(fsBox, 1);
    root->addLayout(bottom, 2);
}

void LiveView::ensureCoreBars(int count) {
    if (coreBars_.size() == count) return;
    for (auto* b : coreBars_) b->deleteLater();
    coreBars_.clear();
    const int columns = count > 16 ? 4 : 2;
    for (int i = 0; i < count; ++i) {
        auto* bar = new QProgressBar;
        bar->setRange(0, 100);
        bar->setFormat(QString("cpu%1  %p%").arg(i));
        bar->setTextVisible(true);
        coreGrid_->addWidget(bar, i / columns, i % columns);
        coreBars_.append(bar);
    }
}

void LiveView::updateFrame(const QJsonObject& f) {
    const auto cpu = f["cpu"].toObject();
    const auto mem = f["memory"].toObject();
    const auto disk = f["disk"].toObject();
    const auto net = f["network"].toObject();
    const auto procs = f["processes"].toObject();

    const double cpuPct = cpu["total"].toDouble();
    const double memPct = mem["used_pct"].toDouble();
    const double swapPct = mem["swap_pct"].toDouble();
    const double rx = net["rx_bps"].toDouble(), tx = net["tx_bps"].toDouble();

    double diskRead = 0, diskWrite = 0;
    for (const auto& v : disk["io"].toArray()) {
        diskRead += v.toObject()["read_bps"].toDouble();
        diskWrite += v.toObject()["write_bps"].toDouble();
    }

    // ---- cards ---------------------------------------------------------
    const auto cores = cpu["cores"].toArray();
    cpuCard_->setValue(QString::number(cpuPct, 'f', 1) + " %", QString("%1 cores · %2 ctx/s")
                                                                    .arg(cores.size())
                                                                    .arg(std::lround(cpu["ctxt_ps"].toDouble())));
    memCard_->setValue(QString::number(memPct, 'f', 1) + " %",
                       humanBytes(mem["used_kb"].toDouble() * 1024) + " / " +
                           humanBytes(mem["total_kb"].toDouble() * 1024));
    swapCard_->setValue(QString::number(swapPct, 'f', 1) + " %",
                        humanBytes(mem["swap_used_kb"].toDouble() * 1024) + " / " +
                            humanBytes(mem["swap_total_kb"].toDouble() * 1024));
    loadCard_->setValue(QString::number(cpu["load1"].toDouble(), 'f', 2),
                        QString("%1 · %2 (5m · 15m)")
                            .arg(cpu["load5"].toDouble(), 0, 'f', 2)
                            .arg(cpu["load15"].toDouble(), 0, 'f', 2));
    procCard_->setValue(QString::number(procs["total"].toInt()),
                        QString("%1 running · %2 threads").arg(procs["running"].toInt()).arg(procs["threads"].toInt()));
    netCard_->setValue("↓ " + humanRate(rx), "↑ " + humanRate(tx) +
                                                 QString(" · %1 TCP").arg(net["tcp_established"].toInt()));
    uptimeCard_->setValue(humanDuration(cpu["uptime"].toDouble()), f["host"].toString());

    // ---- charts --------------------------------------------------------
    usageChart_->append({cpuPct, memPct, swapPct});
    netChart_->append({rx / 1024.0, tx / 1024.0});
    diskChart_->append({diskRead / 1024.0, diskWrite / 1024.0});

    // ---- cores ---------------------------------------------------------
    ensureCoreBars(static_cast<int>(cores.size()));
    for (int i = 0; i < cores.size(); ++i) coreBars_[i]->setValue(static_cast<int>(std::lround(cores[i].toObject()["usage"].toDouble())));

    // ---- filesystems ---------------------------------------------------
    const auto fs = disk["fs"].toArray();
    fsTable_->setRowCount(static_cast<int>(fs.size()));
    for (int r = 0; r < fs.size(); ++r) {
        const auto o = fs[r].toObject();
        const double used = o["used_pct"].toDouble();
        auto set = [&](int c, const QString& text) {
            auto* item = fsTable_->item(r, c);
            if (!item) fsTable_->setItem(r, c, item = new QTableWidgetItem);
            item->setText(text);
            if (c == 3) item->setForeground(used >= 90 ? severityColor("critical")
                                            : used >= 75 ? severityColor("warning")
                                                         : palette().text().color());
        };
        set(0, o["mount"].toString());
        set(1, o["device"].toString());
        set(2, o["type"].toString());
        set(3, QString::number(used, 'f', 1) + " %");
        set(4, humanBytes(o["total"].toDouble()));
    }
    fsTable_->resizeColumnsToContents();
}

}  // namespace sysmon::ui
