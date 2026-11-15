#include "process_view.hpp"

#include <QApplication>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>
#include <cmath>

#include "db/database.hpp"
#include "format.hpp"
#include "widgets.hpp"

namespace sysmon::ui {
namespace {

QTableWidget* makeTable(const QStringList& headers) {
    auto* t = new QTableWidget(0, static_cast<int>(headers.size()));
    t->setHorizontalHeaderLabels(headers);
    t->horizontalHeader()->setStretchLastSection(true);
    t->verticalHeader()->setVisible(false);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setAlternatingRowColors(true);
    t->setSortingEnabled(true);
    return t;
}

/// Item whose DisplayRole is numeric so column sorting is numeric.
QTableWidgetItem* numItem(double v, int decimals = 0) {
    auto* item = new QTableWidgetItem;
    item->setData(Qt::DisplayRole, decimals > 0 ? QVariant(std::round(v * std::pow(10, decimals)) / std::pow(10, decimals))
                                                : QVariant(static_cast<qlonglong>(v)));
    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    return item;
}

/// Item that displays a human readable size but sorts by raw value.
class SizeItem : public QTableWidgetItem {
public:
    explicit SizeItem(double bytes) : QTableWidgetItem(humanBytes(bytes)), bytes_(bytes) {
        setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    }
    bool operator<(const QTableWidgetItem& other) const override {
        if (auto* o = dynamic_cast<const SizeItem*>(&other)) return bytes_ < o->bytes_;
        return QTableWidgetItem::operator<(other);
    }

private:
    double bytes_;
};

}  // namespace

ProcessView::ProcessView(std::shared_ptr<Database> db, QWidget* parent)
    : QWidget(parent),
      db_(std::move(db)),
      filter_(new QLineEdit),
      live_(makeTable({"PID", "PPID", "Name", "User", "State", "CPU %", "Memory", "Threads", "Command"})),
      liveInfo_(new QLabel),
      statsRange_(new RangeCombo),
      stats_(makeTable({"Process", "User", "Samples", "Avg CPU %", "Peak CPU %", "Avg memory", "Peak memory"})),
      statsInfo_(new QLabel) {
    filter_->setPlaceholderText("Filter by name, user, PID or command...");
    filter_->setClearButtonEnabled(true);
    connect(filter_, &QLineEdit::textChanged, this, &ProcessView::applyFilter);
    live_->sortItems(5, Qt::DescendingOrder);  // default: CPU, highest first

    // ---- live -----------------------------------------------------------
    auto* liveBox = new QGroupBox("Live — top processes by CPU");
    auto* liveLayout = new QVBoxLayout(liveBox);
    auto* liveTop = new QHBoxLayout;
    liveTop->addWidget(filter_, 1);
    liveTop->addWidget(liveInfo_);
    liveLayout->addLayout(liveTop);
    liveLayout->addWidget(live_);

    // ---- statistics -----------------------------------------------------
    auto* statsBox = new QGroupBox("Historical process statistics");
    auto* statsLayout = new QVBoxLayout(statsBox);
    auto* statsTop = new QHBoxLayout;
    auto* refresh = new QPushButton("Load statistics");
    statsTop->addWidget(new QLabel("Range:"));
    statsTop->addWidget(statsRange_);
    statsTop->addWidget(refresh);
    statsTop->addWidget(statsInfo_, 1);
    statsLayout->addLayout(statsTop);
    statsLayout->addWidget(stats_);
    connect(refresh, &QPushButton::clicked, this, &ProcessView::refreshStats);

    auto* splitter = new QSplitter(Qt::Vertical);
    splitter->addWidget(liveBox);
    splitter->addWidget(statsBox);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    auto* layout = new QVBoxLayout(this);
    layout->addWidget(splitter);
}

void ProcessView::updateFrame(const QJsonObject& frame) {
    const auto procs = frame["processes"].toObject();
    const auto top = procs["top"].toArray();

    // Preserve the user's sort column while refilling the table.
    const int sortCol = live_->horizontalHeader()->sortIndicatorSection();
    const auto sortOrder = live_->horizontalHeader()->sortIndicatorOrder();
    live_->setSortingEnabled(false);
    live_->setRowCount(static_cast<int>(top.size()));
    for (int r = 0; r < top.size(); ++r) {
        const auto p = top[r].toObject();
        live_->setItem(r, 0, numItem(p["pid"].toInt()));
        live_->setItem(r, 1, numItem(p["ppid"].toInt()));
        live_->setItem(r, 2, new QTableWidgetItem(p["name"].toString()));
        live_->setItem(r, 3, new QTableWidgetItem(p["user"].toString()));
        live_->setItem(r, 4, new QTableWidgetItem(p["state"].toString()));
        live_->setItem(r, 5, numItem(p["cpu"].toDouble(), 1));
        live_->setItem(r, 6, new SizeItem(p["rss_kb"].toDouble() * 1024));
        live_->setItem(r, 7, numItem(p["threads"].toInt()));
        live_->setItem(r, 8, new QTableWidgetItem(p["cmd"].toString()));
    }
    live_->setSortingEnabled(true);
    live_->sortItems(sortCol >= 0 ? sortCol : 5, sortCol >= 0 ? sortOrder : Qt::DescendingOrder);
    liveInfo_->setText(QString("%1 processes · %2 running · showing top %3")
                           .arg(procs["total"].toInt())
                           .arg(procs["running"].toInt())
                           .arg(top.size()));
    applyFilter();
}

void ProcessView::applyFilter() {
    const QString needle = filter_->text().trimmed();
    for (int r = 0; r < live_->rowCount(); ++r) {
        bool match = needle.isEmpty();
        for (int c : {0, 2, 3, 8}) {
            if (match) break;
            if (auto* item = live_->item(r, c); item && item->text().contains(needle, Qt::CaseInsensitive)) match = true;
        }
        live_->setRowHidden(r, !match);
    }
}

void ProcessView::refreshStats() {
    const auto to = Clock::now();
    const auto from = to - statsRange_->range();
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        const auto rows = db_->process_stats(from, to, 100);
        stats_->setSortingEnabled(false);
        stats_->setRowCount(static_cast<int>(rows.size()));
        for (int r = 0; r < static_cast<int>(rows.size()); ++r) {
            const auto& s = rows[static_cast<std::size_t>(r)];
            stats_->setItem(r, 0, new QTableWidgetItem(QString::fromStdString(s.name)));
            stats_->setItem(r, 1, new QTableWidgetItem(QString::fromStdString(s.user)));
            stats_->setItem(r, 2, numItem(static_cast<double>(s.samples)));
            stats_->setItem(r, 3, numItem(s.avg_cpu, 2));
            stats_->setItem(r, 4, numItem(s.max_cpu, 1));
            stats_->setItem(r, 5, new SizeItem(s.avg_rss_kb * 1024));
            stats_->setItem(r, 6, new SizeItem(s.max_rss_kb * 1024));
        }
        stats_->setSortingEnabled(true);
        stats_->resizeColumnsToContents();
        statsInfo_->setText(QString("%1 distinct processes").arg(rows.size()));
    } catch (const std::exception& e) {
        statsInfo_->setText("<span style='color:#d33'>Database error: " + QString::fromUtf8(e.what()).toHtmlEscaped() +
                            "</span>");
    }
    QApplication::restoreOverrideCursor();
}

}  // namespace sysmon::ui
