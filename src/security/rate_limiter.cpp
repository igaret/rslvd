#include "security/rate_limiter.h"
#include "monitoring/logger.h"

RateLimiter::RateLimiter(uint32_t qps, uint32_t qpm, uint32_t max_conn)
    : max_queries_per_second(qps), max_queries_per_minute(qpm), 
      max_concurrent_connections(max_conn), current_connections(0),
      cleanup_running(true) {
   
    cleanup_thread = std::thread(&RateLimiter::cleanupExpiredEntries, this);
}

RateLimiter::~RateLimiter() {
    cleanup_running = false;
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }
}

bool RateLimiter::checkRateLimit(const std::string& client_ip) {
    auto now = std::chrono::steady_clock::now();
   
    // Get or create entry for client
    std::unique_lock<std::shared_mutex> lock(limits_mutex);
   
    auto it = client_limits.find(client_ip);
    if (it == client_limits.end()) {
        auto entry = std::make_unique<RateLimitEntry>();
        entry->queries_per_second = 0;
        entry->queries_per_minute = 0;
        entry->last_second_reset = now;
        entry->last_minute_reset = now;
       
        client_limits[client_ip] = std::move(entry);
        it = client_limits.find(client_ip);
    }
   
    auto& entry = it->second;
    lock.unlock();
   
    std::lock_guard<std::mutex> entry_lock(entry->entry_mutex);
   
    // Reset counters if time windows have passed
    if (now - entry->last_second_reset >= std::chrono::seconds(1)) {
        entry->queries_per_second = 0;
        entry->last_second_reset = now;
    }
   
    if (now - entry->last_minute_reset >= std::chrono::minutes(1)) {
        entry->queries_per_minute = 0;
        entry->last_minute_reset = now;
    }
   
    // Check limits
    if (entry->queries_per_second >= max_queries_per_second ||
        entry->queries_per_minute >= max_queries_per_minute) {
       
        Logger::getInstance().logSecurityEvent("RATE_LIMIT_EXCEEDED", client_ip,
            "qps=" + std::to_string(entry->queries_per_second.load()) +
            " qpm=" + std::to_string(entry->queries_per_minute.load()));
       
        return false;
    }
   
    // Increment counters
    entry->queries_per_second++;
    entry->queries_per_minute++;
   
    return true;
}

bool RateLimiter::checkConnectionLimit() {
    return current_connections < max_concurrent_connections;
}

void RateLimiter::incrementConnections() {
    current_connections++;
}

void RateLimiter::decrementConnections() {
    if (current_connections > 0) {
        current_connections--;
    }
}

void RateLimiter::updateLimits(uint32_t qps, uint32_t qpm, uint32_t max_conn) {
    max_queries_per_second = qps;
    max_queries_per_minute = qpm;
    max_concurrent_connections = max_conn;
}

void RateLimiter::cleanupExpiredEntries() {
    while (cleanup_running) {
        std::this_thread::sleep_for(std::chrono::minutes(5));
       
        auto now = std::chrono::steady_clock::now();
        std::unique_lock<std::shared_mutex> lock(limits_mutex);
       
        auto it = client_limits.begin();
        while (it != client_limits.end()) {
            auto& entry = it->second;
           
            // Remove entries that haven't been accessed for 10 minutes
            if (now - entry->last_minute_reset > std::chrono::minutes(10)) {
                it = client_limits.erase(it);
            } else {
                ++it;
            }
        }
    }
}

RateLimiter::Stats RateLimiter::getStats() const {
    std::shared_lock<std::shared_mutex> lock(limits_mutex);
   
    Stats stats;
    stats.total_clients = static_cast<uint32_t>(client_limits.size());
    stats.current_connections = current_connections.load();
    stats.blocked_queries = 0; // Would need additional tracking
    stats.blocked_connections = 0; // Would need additional tracking
   
    return stats;
}

void RateLimiter::resetStats() {
    std::unique_lock<std::shared_mutex> lock(limits_mutex);
    client_limits.clear();
    current_connections = 0;
}