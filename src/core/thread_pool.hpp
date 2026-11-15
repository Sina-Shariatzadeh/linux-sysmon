#pragma once

#include <algorithm>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>

namespace sysmon {

/// Fixed-size pool of worker threads. `submit` returns a std::future so the
/// caller can fan out work (e.g. one task per collector) and join on the
/// results. Exceptions thrown by a task are delivered through its future.
/// The destructor finishes all queued tasks before joining.
class ThreadPool {
public:
    explicit ThreadPool(std::size_t threads = std::max(1u, std::thread::hardware_concurrency())) {
        if (threads == 0) threads = 1;
        workers_.reserve(threads);
        for (std::size_t i = 0; i < threads; ++i) workers_.emplace_back([this] { worker_loop(); });
    }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    ~ThreadPool() {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        cv_.notify_all();
        // std::jthread joins on destruction.
    }

    template <typename F>
    auto submit(F&& fn) -> std::future<std::invoke_result_t<std::decay_t<F>>> {
        using R = std::invoke_result_t<std::decay_t<F>>;
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(fn));
        std::future<R> fut = task->get_future();
        {
            std::lock_guard lock(mutex_);
            if (stopping_) throw std::runtime_error("ThreadPool: submit after shutdown");
            tasks_.emplace([task] { (*task)(); });
        }
        cv_.notify_one();
        return fut;
    }

    std::size_t size() const { return workers_.size(); }

    std::size_t pending() const {
        std::lock_guard lock(mutex_);
        return tasks_.size();
    }

private:
    void worker_loop() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock lock(mutex_);
                cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
                if (tasks_.empty()) return;  // stopping and drained
                task = std::move(tasks_.front());
                tasks_.pop();
            }
            task();  // packaged_task captures exceptions
        }
    }

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::function<void()>> tasks_;
    bool stopping_ = false;
    std::vector<std::jthread> workers_;  // declared last: joined first on destruction
};

}  // namespace sysmon
