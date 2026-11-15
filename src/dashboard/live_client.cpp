#include "live_client.hpp"

#include <QJsonDocument>
#include <QJsonParseError>

namespace sysmon::ui {

LiveClient::LiveClient(QString host, quint16 port, QObject* parent)
    : QObject(parent), host_(std::move(host)), port_(port) {
    reconnectTimer_.setInterval(3000);
    reconnectTimer_.setSingleShot(true);
    connect(&reconnectTimer_, &QTimer::timeout, this, &LiveClient::connectNow);

    connect(&socket_, &QTcpSocket::connected, this, [this] {
        buffer_.clear();
        emit connectionChanged(true, "Live: connected to " + endpoint());
    });
    connect(&socket_, &QTcpSocket::disconnected, this, [this] {
        emit connectionChanged(false, "Live: disconnected from " + endpoint() + ", retrying...");
        reconnectTimer_.start();
    });
    connect(&socket_, &QTcpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        emit connectionChanged(false, "Live: " + socket_.errorString() + " (" + endpoint() + "), retrying...");
        if (socket_.state() == QAbstractSocket::UnconnectedState) reconnectTimer_.start();
    });
    connect(&socket_, &QTcpSocket::readyRead, this, &LiveClient::onReadyRead);
}

void LiveClient::start() { connectNow(); }

void LiveClient::connectNow() {
    if (socket_.state() != QAbstractSocket::UnconnectedState) return;
    emit connectionChanged(false, "Live: connecting to " + endpoint() + "...");
    socket_.connectToHost(host_, port_);
}

void LiveClient::onReadyRead() {
    buffer_.append(socket_.readAll());
    qsizetype nl;
    while ((nl = buffer_.indexOf('\n')) >= 0) {
        const QByteArray line = buffer_.left(nl);
        buffer_.remove(0, nl + 1);
        if (line.trimmed().isEmpty()) continue;

        QJsonParseError err{};
        const auto doc = QJsonDocument::fromJson(line, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject()) continue;
        const auto obj = doc.object();
        const auto type = obj.value("type").toString();
        if (type == "frame") emit frameReceived(obj);
        else if (type == "event" || type == "alert") emit eventReceived(obj);
    }
    if (buffer_.size() > 16 * 1024 * 1024) buffer_.clear();  // protocol garbage guard
}

}  // namespace sysmon::ui
