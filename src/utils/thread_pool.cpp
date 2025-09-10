#include "utils/thread_pool.h"
#include "monitoring/logger.h"

ThreadPool::ThreadPool(size_t num_threads) : stop(false), active_tasks(0) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back([this] {
            for (;;) {
                std::function<void()> task;
               
                {
                    std::unique_lock<std::mutex> lock(queue_mutex);
                    condition.wait(lock, [this] { return stop || !tasks.empty(); });
                   
                    if (stop && tasks.empty()) {
                        return;
                    }
                   
                    task = std::move(tasks.front());
                    tasks.pop();
                }
               
                active_tasks++;
                try {
                    task();
                } catch (const std::exception& e) {
                    LOG_ERROR("Task execution failed: " + std::string(e.what()), "THREADPOOL");
                } catch (...) {
                    LOG_ERROR("Task execution failed with unknown exception", "THREADPOOL");
                }
                active_tasks--;
            }
        });
    }
   
    LOG_INFO("ThreadPool initialized with " + std::to_string(num_threads) + " threads", "THREADPOOL");
}

ThreadPool::~ThreadPool() {
    shutdown();
}

size_t ThreadPool::getQueueSize() const {
    std::unique_lock<std::mutex> lock(queue_mutex);
    return tasks.size();
}

void ThreadPool::shutdown() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true;
    }
   
    condition.notify_all();
   
    for (std::thread& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
   
    workers.clear();
}
