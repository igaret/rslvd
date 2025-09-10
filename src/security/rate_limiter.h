#pragma once
#include "utils/utils.h"

struct RateLimitEntry {
    std::atomic<uint32_t> queries_per_second;
    std::atomic<uint32_t> queries_per_minute;
    std::chrono::steady_clock::time_point last_second_reset;
    std::chrono::steady_clock::time_point last_minute_reset;
    std::mutex entry_mutex;
};

class RateLimiter {
private:
    std::unordered_map<std::string, std::unique_ptr<RateLimitEntry>> client_limits;
    mutable std::shared_mutex limits_mutex;
   
    uint32_t max_queries_per_second;
    uint32_t max_queries_per_minute;
    uint32_t max_concurrent_connections;
    std::atomic<uint32_t> current_connections;
   
    // Cleanup thread
    std::thread cleanup_thread;
    std::atomic<bool> cleanup_running;
   
    void cleanupExpiredEntries();
   
public:
    RateLimiter(uint32_t qps = MAX_QUERIES_PER_SECOND, 
                uint32_t qpm = MAX_QUERIES_PER_MINUTE,
                uint32_t max_conn = MAX_CONCURRENT_CONNECTIONS);
    ~RateLimiter();
   
    bool checkRateLimit(const std::string& client_ip);
    bool checkConnectionLimit();
    void incrementConnections();
    void decrementConnections();
   
    void updateLimits(uint32_t qps, uint32_t qpm, uint32_t max_conn);
   
    // Statistics
    struct Stats {
        uint32_t total_clients;
        uint32_t current_connections;
        uint32_t blocked_queries;
        uint32_t blocked_connections;
    };
   
    Stats getStats() const;
    void resetStats();
};