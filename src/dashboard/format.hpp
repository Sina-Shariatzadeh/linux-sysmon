#pragma once

#include <QColor>
#include <QDateTime>
#include <QString>

namespace sysmon::ui {

inline QString humanBytes(double bytes) {
    static const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
    int u = 0;
    while (bytes >= 1024.0 && u < 5) {
        bytes /= 1024.0;
        ++u;
    }
    return QString::number(bytes, 'f', u == 0 ? 0 : 1) + ' ' + units[u];
}

inline QString humanRate(double bytesPerSec) { return humanBytes(bytesPerSec) + "/s"; }

inline QString humanDuration(double seconds) {
    const auto s = static_cast<long long>(seconds);
    const long long d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60;
    if (d > 0) return QString("%1d %2h %3m").arg(d).arg(h).arg(m);
    if (h > 0) return QString("%1h %2m").arg(h).arg(m);
    return QString("%1m %2s").arg(m).arg(s % 60);
}

inline QString formatTime(double epochSeconds) {
    return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(epochSeconds * 1000.0)).toString("yyyy-MM-dd HH:mm:ss");
}

inline QColor severityColor(const QString& severity) {
    if (severity == "critical") return QColor(220, 53, 69);
    if (severity == "warning") return QColor(230, 160, 20);
    return QColor(70, 130, 200);
}

}  // namespace sysmon::ui
