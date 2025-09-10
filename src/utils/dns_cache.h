#pragma once
#include "utils/utils.h"
#include "dns_record.h"

struct CacheEntry {
    std::vector<DNSRecord> records;
    std::chrono::steady_clock::time_point inserted;
    std::chrono::steady_clock::time_point expires;
    uint32_t hit_count;
   
    CacheEntry(const std::vector<DNSRecord>& recs, uint32_t ttl)
        : records(recs), inserted(std::chrono::steady_clock::now()),
          expires(inserted + std::chrono::seconds(ttl)), hit_count(0) {}
   
    bool isExpired() const {
        return std::chrono::steady_clock::now() >= expires;
    }
};

class DNSCache {
private:
    std::unordered_map<std::string, std::unique_ptr<CacheEntry>> cache;
    mutable std::shared_mutex cache_mutex;
   
    size_t max_entries;
    size_t max_memory_mb;
    std::atomic<size_t> current_memory_usage;
   
    std::thread cleanup_thread;
    std::atomic<bool> cleanup_running;
   
    // Statistics
    std::atomic<uint64_t> cache_hits;
    std::atomic<uint64_t> cache_misses;
    std::atomic<uint64_t> cache_evictions;
   
    void cleanupExpiredEntries();
    void evictLRUEntries();
    std::string makeCacheKey(const std::string& name, uint16_t type) const;
    size_t estimateEntrySize(const CacheEntry& entry) const;
   
public:
    DNSCache(size_t max_entries = 10000, size_t max_memory_mb = 100);
    ~DNSCache();
   
    void put(const std::string& name, uint16_t type, 
             const std::vector<DNSRecord>& records, uint32_t ttl);
    std::vector<DNSRecord> get(const std::string& name, uint16_t type);
   
    void remove(const std::string& name, uint16_t type);
    void clear();
   
    // Statistics
    struct CacheStats {
        uint64_t hits;
        uint64_t misses;
        uint64_t evictions;
        size_t entries;
        size_t memory_usage_mb;
        double hit_ratio;
    };
   
    CacheStats getStats() const;
    void resetStats();
   
    // Configuration
    void setMaxEntries(size_t max_entries);
    void setMaxMemory(size_t max_memory_mb);
};