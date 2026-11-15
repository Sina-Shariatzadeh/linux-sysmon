#include "event_view.hpp"

#include <QApplication>
#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include "db/database.hpp"
#include "format.hpp"
#include "widgets.hpp"

namespace sysmon::ui {
namespace {

int severityRank(const QString& s) {
    if (s == "critical") return 2;
    if (s == "warning") return 1;
    return 0;
}

constexpr int kMaxRows = 2000;

}  // namespace

EventView::EventView(std::shared_ptr<Database> db, QWidget* parent)
    : QWidget(parent),
      db_(std::move(db)),
      query_(new QLineEdit),
      severity_(new QComboBox),
      range_(new RangeCombo(nullptr, 3)),
      table_(new QTableWidget(0, 5)),
      info_(new QLabel) {
    query_->setPlaceholderText("Search messages, categories, metrics (e.g. brute_force, sshd, 10.0.0.5)...");
    query_->setClearButtonEnabled(true);
    severity_->addItem("All severities", 0);
    severity_->addItem("Warning and above", 1);
    severity_->addItem("Critical only", 2);

    auto* searchBtn = new QPushButton("Search");
    auto* controls = new QHBoxLayout;
    controls->addWidget(query_, 1);
    controls->addWidget(severity_);
    controls->addWidget(range_);
    controls->addWidget(searchBtn);

    table_->setHorizontalHeaderLabels({"Time", "Kind", "Severity", "Category / metric", "Message"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setWordWrap(false);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(controls);
    layout->addWidget(table_, 1);
    layout->addWidget(info_);

    connect(searchBtn, &QPushButton::clicked, this, &EventView::search);
    connect(query_, &QLineEdit::returnPressed, this, &EventView::search);
    connect(severity_, &QComboBox::currentIndexChanged, this, &EventView::search);
    connect(range_, &QComboBox::currentIndexChanged, this, &EventView::search);
}

int EventView::minSeverity() const { return severity_->currentData().toInt(); }

void EventView::insertRow(int row, double ts, const QString& kind, const QString& severity, const QString& subject,
                          const QString& message) {
    table_->insertRow(row);
    const QColor color = severityColor(severity);
    const QStringList cells{formatTime(ts), kind, severity, subject, message};
    for (int c = 0; c < cells.size(); ++c) {
        auto* item = new QTableWidgetItem(cells[c]);
        if (c == 2) {
            item->setForeground(color);
            QFont f = item->font();
            f.setBold(true);
            item->setFont(f);
        }
        item->setToolTip(c == 4 ? message : QString());
        table_->setItem(row, c, item);
    }
}

void EventView::search() {
    const auto to = Clock::now();
    const auto from = to - range_->range();
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        const auto rows = db_->search_events(query_->text().trimmed().toStdString(),
                                             static_cast<Severity>(minSeverity()), from, to, kMaxRows);
        table_->setRowCount(0);
        for (const auto& e : rows)
            insertRow(table_->rowCount(), e.ts, QString::fromStdString(e.kind), QString::fromStdString(e.severity),
                      QString::fromStdString(e.subject), QString::fromStdString(e.message));
        table_->resizeColumnsToContents();
        info_->setText(QString("%1 result(s)%2").arg(rows.size()).arg(rows.size() >= static_cast<std::size_t>(kMaxRows) ? " (truncated)" : ""));
    } catch (const std::exception& e) {
        info_->setText("<span style='color:#d33'>Database error: " + QString::fromUtf8(e.what()).toHtmlEscaped() +
                       "</span>");
    }
    QApplication::restoreOverrideCursor();
}

void EventView::addLiveEvent(const QJsonObject& ev) {
    const bool isAlert = ev["type"].toString() == "alert";
    const QString severity = ev["severity"].toString();
    const QString subject = isAlert ? ev["metric"].toString() : ev["category"].toString();
    const QString message = ev["message"].toString();

    if (severity == "critical") emit criticalEventReceived(message);
    if (severityRank(severity) < minSeverity()) return;
    const QString needle = query_->text().trimmed();
    if (!needle.isEmpty() && !message.contains(needle, Qt::CaseInsensitive) &&
        !subject.contains(needle, Qt::CaseInsensitive))
        return;

    insertRow(0, ev["ts"].toDouble(), isAlert ? "alert" : "security", severity, subject, message);
    if (table_->rowCount() > kMaxRows) table_->setRowCount(kMaxRows);
}

}  // namespace sysmon::ui
