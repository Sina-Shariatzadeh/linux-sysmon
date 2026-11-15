#include <gtest/gtest.h>

#include <atomic>
#include <numeric>
#include <thread>

#include "core/blocking_queue.hpp"
#include "core/thread_pool.hpp"

using namespace sysmon;

TEST(ThreadPool, ReturnsResultsThroughFutures) {
    ThreadPool pool(4);
    std::vector<std::future<int>> futures;
    for (int i = 0; i < 100; ++i) futures.push_back(pool.submit([i] { return i * i; }));
    long sum = 0;
    for (auto& f : futures) sum += f.get();
    EXPECT_EQ(sum, 328350);  // sum of squares 0..99
}

TEST(ThreadPool, RunsTasksConcurrently) {
    ThreadPool pool(4);
    std::atomic<int> running{0}, peak{0};
    std::vector<std::future<void>> fs;
    for (int i = 0; i < 4; ++i)
        fs.push_back(pool.submit([&] {
            const int now = ++running;
            int p = peak.load();
            while (now > p && !peak.compare_exchange_weak(p, now)) {}
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            --running;
        }));
    for (auto& f : fs) f.get();
    EXPECT_GE(peak.load(), 2);
}

TEST(ThreadPool, PropagatesExceptions) {
    ThreadPool pool(2);
    auto f = pool.submit([]() -> int { throw std::runtime_error("boom"); });
    EXPECT_THROW(f.get(), std::runtime_error);
    // Pool remains usable afterwards.
    EXPECT_EQ(pool.submit([] { return 7; }).get(), 7);
}

TEST(ThreadPool, DestructorDrainsQueue) {
    std::atomic<int> done{0};
    {
        ThreadPool pool(1);
        for (int i = 0; i < 50; ++i) pool.submit([&] { ++done; });
    }
    EXPECT_EQ(done.load(), 50);
}

TEST(BlockingQueue, FifoAndClose) {
    BlockingQueue<int> q(10);
    q.push(1);
    q.push(2);
    EXPECT_EQ(q.pop(), 1);
    EXPECT_EQ(q.pop(), 2);
    q.close();
    EXPECT_FALSE(q.pop().has_value());
    EXPECT_FALSE(q.push(3));
}

TEST(BlockingQueue, DropsOldestWhenFull) {
    BlockingQueue<int> q(3);
    for (int i = 1; i <= 5; ++i) q.push(i);
    EXPECT_EQ(q.size(), 3u);
    EXPECT_EQ(q.dropped(), 2u);
    EXPECT_EQ(q.pop(), 3);
}

TEST(BlockingQueue, PopForTimesOut) {
    BlockingQueue<int> q;
    const auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(q.pop_for(std::chrono::milliseconds(50)).has_value());
    EXPECT_GE(std::chrono::steady_clock::now() - start, std::chrono::milliseconds(45));
}

TEST(BlockingQueue, ProducerConsumerAcrossThreads) {
    BlockingQueue<int> q(100000);
    std::atomic<long> sum{0};
    std::thread consumer([&] {
        while (auto v = q.pop()) sum += *v;
    });
    std::vector<std::thread> producers;
    for (int t = 0; t < 4; ++t)
        producers.emplace_back([&] {
            for (int i = 1; i <= 1000; ++i) q.push(i);
        });
    for (auto& p : producers) p.join();
    q.close();
    consumer.join();
    EXPECT_EQ(sum.load(), 4L * 500500);
}
