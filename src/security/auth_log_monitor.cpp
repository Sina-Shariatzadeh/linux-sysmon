#include "security/auth_log_monitor.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <condition_variable>

namespace sysmon {

AuthLogMonitor::AuthLogMonitor(std::vector<std::string> candidate_paths, Callback cb,
                               std::chrono::milliseconds poll_interval)
    : paths_(std::move(candidate_paths)), cb_(std::move(cb)), poll_(poll_interval) {}

AuthLogMonitor::~AuthLogMonitor() { stop(); }

void AuthLogMonitor::start() {
    if (thread_.joinable()) return;
    thread_ = std::jthread([this](std::stop_token st) { run(st); });
}

void AuthLogMonitor::stop() {
    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }
}

std::string AuthLogMonitor::active_path() const {
    std::lock_guard lock(mutex_);
    return active_;
}

void AuthLogMonitor::process_line(const std::string& line) {
    if (auto failure = parsers::parse_auth_failure(line)) cb_(*failure);
}

void AuthLogMonitor::run(std::stop_token st) {
    int fd = -1;
    ino_t inode = 0;
    off_t offset = 0;
    std::string partial;
    bool first_open = true;

    std::mutex sleep_mutex;
    std::condition_variable_any sleep_cv;

    auto close_fd = [&] {
        if (fd >= 0) ::close(fd);
        fd = -1;
    };

    while (!st.stop_requested()) {
        if (fd < 0) {
            for (const auto& p : paths_) {
                fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
                if (fd < 0) continue;
                struct stat sb {};
                ::fstat(fd, &sb);
                inode = sb.st_ino;
                // On the very first open skip existing history; after a rotation
                // read the new file from the beginning.
                offset = first_open ? sb.st_size : 0;
                ::lseek(fd, offset, SEEK_SET);
                partial.clear();
                std::lock_guard lock(mutex_);
                active_ = p;
                break;
            }
            first_open = false;
        }

        if (fd >= 0) {
            char buf[8192];
            ssize_t n;
            while ((n = ::read(fd, buf, sizeof buf)) > 0) {
                offset += n;
                partial.append(buf, static_cast<std::size_t>(n));
                std::size_t start = 0, nl;
                while ((nl = partial.find('\n', start)) != std::string::npos) {
                    process_line(partial.substr(start, nl - start));
                    start = nl + 1;
                }
                partial.erase(0, start);
                if (partial.size() > 65536) partial.clear();  // garbage without newlines
            }

            // Rotation / truncation detection.
            std::string path;
            {
                std::lock_guard lock(mutex_);
                path = active_;
            }
            struct stat sb {};
            if (::stat(path.c_str(), &sb) != 0 || sb.st_ino != inode || sb.st_size < offset) close_fd();
        }

        std::unique_lock lock(sleep_mutex);
        sleep_cv.wait_for(lock, st, poll_, [] { return false; });
    }
    close_fd();
}

}  // namespace sysmon
