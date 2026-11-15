#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>

namespace sysmon {

/// Bounded multi-producer / multi-consumer queue. When full, the *oldest*
/// element is dropped so a slow consumer (e.g. an unreachable database)
/// can never make the producer block or memory grow without bound.
template <typename T>
class BlockingQueue {
public:
    explicit BlockingQueue(std::size_t capacity = 1024) : capacity_(capacity ? capacity : 1) {}

    /// Returns false if the element was pushed but an old one had to be dropped,
    /// or if the queue is closed (element discarded).
    bool push(T value) {
        bool dropped = false;
        {
            std::lock_guard lock(mutex_);
            if (closed_) return false;
            if (queue_.size() >= capacity_) {
                queue_.pop_front();
                ++dropped_;
                dropped = true;
            }
            queue_.push_back(std::move(value));
        }
        cv_.notify_one();
        return !dropped;
    }

    /// Blocks until an element is available or the queue is closed and empty.
    std::optional<T> pop() {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [this] { return closed_ || !queue_.empty(); });
        return take_locked();
    }

    template <typename Rep, typename Period>
    std::optional<T> pop_for(std::chrono::duration<Rep, Period> timeout) {
        std::unique_lock lock(mutex_);
        cv_.wait_for(lock, timeout, [this] { return closed_ || !queue_.empty(); });
        return take_locked();
    }

    void close() {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        cv_.notify_all();
    }

    std::size_t size() const {
        std::lock_guard lock(mutex_);
        return queue_.size();
    }

    std::size_t dropped() const {
        std::lock_guard lock(mutex_);
        return dropped_;
    }

    bool closed() const {
        std::lock_guard lock(mutex_);
        return closed_;
    }

private:
    std::optional<T> take_locked() {
        if (queue_.empty()) return std::nullopt;
        T v = std::move(queue_.front());
        queue_.pop_front();
        return v;
    }

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<T> queue_;
    std::size_t capacity_;
    std::size_t dropped_ = 0;
    bool closed_ = false;
};

}  // namespace sysmon
