#include "daemon/live_server.hpp"

#include <array>
#include <deque>

#include "core/log.hpp"

namespace sysmon {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// ---------------------------------------------------------------- Session --
class LiveServer::Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, LiveServer& server) : socket_(std::move(socket)), server_(server) {}

    void start() { read_loop(); }

    void send(Message msg) {
        if (closed_) return;
        // Client too slow: drop the oldest message that is not currently being written.
        if (outbox_.size() >= kMaxQueued) outbox_.erase(outbox_.begin() + 1);
        outbox_.push_back(std::move(msg));
        if (outbox_.size() == 1) write_loop();
    }

    void close() {
        if (closed_) return;
        closed_ = true;
        boost::system::error_code ec;
        socket_.shutdown(tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }

    std::string peer() const {
        boost::system::error_code ec;
        auto ep = socket_.remote_endpoint(ec);
        return ec ? "?" : ep.address().to_string() + ":" + std::to_string(ep.port());
    }

private:
    static constexpr std::size_t kMaxQueued = 64;

    void write_loop() {
        auto self = shared_from_this();
        asio::async_write(socket_, asio::buffer(*outbox_.front()),
                          [this, self](boost::system::error_code ec, std::size_t) {
                              if (ec) return fail();
                              outbox_.pop_front();
                              if (!outbox_.empty()) write_loop();
                          });
    }

    void read_loop() {
        // The protocol is push-only; reads just detect disconnects.
        auto self = shared_from_this();
        socket_.async_read_some(asio::buffer(read_buf_), [this, self](boost::system::error_code ec, std::size_t) {
            if (ec) return fail();
            read_loop();
        });
    }

    void fail() {
        if (closed_) return;
        close();
        server_.remove(shared_from_this());
    }

    tcp::socket socket_;
    LiveServer& server_;
    std::deque<Message> outbox_;
    std::array<char, 512> read_buf_{};
    bool closed_ = false;
};

// ------------------------------------------------------------- LiveServer --
LiveServer::LiveServer(const std::string& bind_address, uint16_t port)
    : work_(asio::make_work_guard(io_)), acceptor_(io_) {
    const tcp::endpoint ep(asio::ip::make_address(bind_address), port);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
}

LiveServer::~LiveServer() { stop(); }

uint16_t LiveServer::port() const { return acceptor_.local_endpoint().port(); }

void LiveServer::start() {
    if (thread_.joinable()) return;
    do_accept();
    thread_ = std::thread([this] {
        try {
            io_.run();
        } catch (const std::exception& e) {
            log::error("live server crashed: ", e.what());
        }
    });
}

void LiveServer::stop() {
    if (!thread_.joinable()) return;
    asio::post(io_, [this] {
        boost::system::error_code ec;
        acceptor_.close(ec);
        for (auto& s : sessions_) s->close();
        sessions_.clear();
        clients_ = 0;
        work_.reset();
    });
    thread_.join();
}

void LiveServer::do_accept() {
    acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
        if (ec) {
            if (ec != asio::error::operation_aborted) log::warn("accept failed: ", ec.message());
            if (acceptor_.is_open()) do_accept();
            return;
        }
        boost::system::error_code nd;
        socket.set_option(tcp::no_delay(true), nd);
        auto session = std::make_shared<Session>(std::move(socket), *this);
        sessions_.insert(session);
        clients_ = sessions_.size();
        log::info("live client connected: ", session->peer(), " (", sessions_.size(), " total)");
        session->start();
        if (last_) session->send(last_);
        do_accept();
    });
}

void LiveServer::remove(const std::shared_ptr<Session>& s) {
    if (sessions_.erase(s)) {
        clients_ = sessions_.size();
        log::info("live client disconnected (", sessions_.size(), " remaining)");
    }
}

void LiveServer::broadcast(std::string line, bool remember) {
    line.push_back('\n');
    auto msg = std::make_shared<const std::string>(std::move(line));
    asio::post(io_, [this, msg, remember] {
        if (remember) last_ = msg;
        for (auto& s : sessions_) s->send(msg);
    });
}

}  // namespace sysmon
