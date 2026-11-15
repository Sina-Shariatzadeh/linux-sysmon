#include "collectors/collectors.hpp"

namespace sysmon {

NetworkCollector::NetworkCollector(std::string proc_root, bool include_loopback)
    : root_(std::move(proc_root)), include_loopback_(include_loopback) {
    if (auto text = parsers::read_file(root_ + "/net/dev"))
        for (auto& n : parsers::parse_net_dev(*text)) prev_[n.iface] = n;
    prev_time_ = SteadyClock::now();
}

NetworkSnapshot NetworkCollector::sample() {
    NetworkSnapshot snap;
    const auto now = SteadyClock::now();
    const double secs = std::chrono::duration<double>(now - prev_time_).count();

    if (auto text = parsers::read_file(root_ + "/net/dev")) {
        std::map<std::string, NetCounters> current;
        for (auto& n : parsers::parse_net_dev(*text)) {
            if (n.iface == "lo" && !include_loopback_) continue;
            auto it = prev_.find(n.iface);
            if (it != prev_.end() && secs > 0) {
                const auto& p = it->second;
                auto rate = [secs](uint64_t a, uint64_t b) { return b >= a ? static_cast<double>(b - a) / secs : 0.0; };
                NetRate r;
                r.iface = n.iface;
                r.rx_bps = rate(p.rx_bytes, n.rx_bytes);
                r.tx_bps = rate(p.tx_bytes, n.tx_bytes);
                r.rx_pps = rate(p.rx_packets, n.rx_packets);
                r.tx_pps = rate(p.tx_packets, n.tx_packets);
                r.rx_errs = n.rx_errs;
                r.tx_errs = n.tx_errs;
                snap.total_rx_bps += r.rx_bps;
                snap.total_tx_bps += r.tx_bps;
                snap.interfaces.push_back(std::move(r));
            }
            current[n.iface] = std::move(n);
        }
        prev_ = std::move(current);
    }
    prev_time_ = now;

    parsers::TcpSummary tcp;
    for (const char* file : {"/net/tcp", "/net/tcp6"})
        if (auto text = parsers::read_file(root_ + file)) parsers::accumulate_proc_net_tcp(*text, tcp);
    snap.tcp_established = tcp.established;
    snap.tcp_listen = tcp.listen;
    snap.tcp_time_wait = tcp.time_wait;
    snap.tcp_total = tcp.total;
    snap.listen_ports.assign(tcp.listen_ports.begin(), tcp.listen_ports.end());
    return snap;
}

}  // namespace sysmon
