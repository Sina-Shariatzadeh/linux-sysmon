#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QObject>
#include <QTcpSocket>
#include <QTimer>

namespace sysmon::ui {

/// Connects to sysmond's live stream (newline-delimited JSON over TCP) and
/// re-emits each message as a signal. Reconnects automatically.
class LiveClient : public QObject {
    Q_OBJECT
public:
    LiveClient(QString host, quint16 port, QObject* parent = nullptr);
    void start();
    QString endpoint() const { return QString("%1:%2").arg(host_).arg(port_); }

signals:
    void frameReceived(const QJsonObject& frame);
    void eventReceived(const QJsonObject& eventOrAlert);
    void connectionChanged(bool connected, const QString& message);

private:
    void onReadyRead();
    void connectNow();

    QString host_;
    quint16 port_;
    QTcpSocket socket_;
    QTimer reconnectTimer_;
    QByteArray buffer_;
};

}  // namespace sysmon::ui
