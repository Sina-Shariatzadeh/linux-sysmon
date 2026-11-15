#pragma once

#include <atomic>
#include <boost/asio.hpp>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <thread>

namespace sysmon {

/// Streams newline-delimited JSON messages (frames, events, alerts) to any
/// number of TCP clients, e.g. the Qt dashboard or `nc 127.0.0.1 9090`.
///
/// All socket work happens on one Boost.Asio io_context thread; broadcast()
/// may be called from any thread. Slow clients get messages dropped instead
/// of stalling the collection engine.
class LiveServer {
public:
    LiveServer(const std::string& bind_address, uint16_t port);
    ~LiveServer();

    LiveServer(const LiveServer&) = delete;
    LiveServer& operator=(const LiveServer&) = delete;

    void start();
    void stop();

    /// Sends `line` (without trailing newline) to every client. When
    /// `remember` is set it is also replayed to clients that connect later
    /// (used for the latest frame so the dashboard fills immediately).
    void broadcast(std::string line, bool remember = false);

    std::size_t client_count() const { return clients_.load(); }
    uint16_t port() const;

private:
    class Session;
    using Message = std::shared_ptr<const std::string>;

    void do_accept();
    void remove(const std::shared_ptr<Session>& s);

    boost::asio::io_context io_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::set<std::shared_ptr<Session>> sessions_;  // io thread only
    Message last_;                                 // io thread only
    std::atomic<std::size_t> clients_{0};
    std::thread thread_;
};

}  // namespace sysmon
