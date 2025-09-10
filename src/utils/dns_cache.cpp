#include "cache/dns_cache.h"
#include "monitoring/logger.h"

DNSCache::DNSCache(size_t max_ent, size_t max_mem) 
    : max_entries(max_ent), max_memory_mb(max_mem), current_memory_usage(0),
      cleanup_running(true), cache_hits(0), cache_misses(0), cache_evictions(0) {
   
    cleanup_thread = std::thread(&DNSCache::cleanupExpiredEntries, this);
    LOG_INFO("DNS Cache initialized with max_entries=" + std::to_string(max_entries) +
             " max_memory=" + std::to_string(max_memory_mb) + "MB", "CACHE");
}

DNSCache::~DNSCache() {
    cleanup_running = false;
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }
}

void DNSCache::put(const std::string& name, uint16_t type,
                   const std::vector<DNSRecord>& records, uint32_t ttl) {
    if (records.empty() || ttl == 0) {
        return;
    }
   
    std::string key = makeCacheKey(name, type);
    auto entry = std::make_unique<CacheEntry>(records, ttl);
    size_t entry_size = estimateEntrySize(*entry);
   
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
   
    // Check if we need to evict entries
    while ((cache.size() >= max_entries || 
            current_memory_usage + entry_size > max_memory_mb * 1024 * 1024) &&
           !cache.empty()) {
        evictLRUEntries();
    }
   
    // Remove existing entry if present
    auto it = cache.find(key);
    if (it != cache.end()) {
        current_memory_usage -= estimateEntrySize(*it->second);
        cache.erase(it);
    }
   
    // Add new entry
    current_memory_usage += entry_size;
    cache[key] = std::move(entry);
}

std::vector<DNSRecord> DNSCache::get(const std::string& name, uint16_t type) {
    std::string key = makeCacheKey(name, type);
   
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
   
    auto it = cache.find(key);
    if (it == cache.end()) {
        cache_misses++;
        return {};
    }
   
    auto& entry = it->second;
    if (entry->isExpired()) {
        lock.unlock();
       
        // Upgrade to write lock and remove expired entry
        std::unique_lock<std::shared_mutex> write_lock(cache_mutex);
        auto write_it = cache.find(key);
        if (write_it != cache.end() && write_it->second->isExpired()) {
            current_memory_usage -= estimateEntrySize(*write_it->second);
            cache.erase(write_it);
        }
       
        cache_misses++;
        return {};
    }
   
    entry->hit_count++;
    cache_hits++;
   
    // Update TTL for returned records
    auto now = std::chrono::steady_clock::now();
    auto remaining_ttl = std::chrono::duration_cast<std::chrono::seconds>(
        entry->expires - now).count();
   
    std::vector<DNSRecord> result = entry->records;
    for (auto& record : result) {
        record.ttl = static_cast<uint32_t>(std::max(1L, remaining_ttl));
    }
   
    return result;
}

void DNSCache::remove(const std::string& name, uint16_t type) {
    std::string key = makeCacheKey(name, type);
   
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
   
    auto it = cache.find(key);
    if (it != cache.end()) {
        current_memory_usage -= estimateEntrySize(*it->second);
        cache.erase(it);
    }
}

void DNSCache::clear() {
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    cache.clear();
    current_memory_usage = 0;
    LOG_INFO("DNS Cache cleared", "CACHE");
}

void DNSCache::cleanupExpiredEntries() {
    while (cleanup_running) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
       
        std::unique_lock<std::shared_mutex> lock(cache_mutex);
       
        auto it = cache.begin();
        while (it != cache.end()) {
            if (it->second->isExpired()) {
                current_memory_usage -= estimateEntrySize(*it->second);
                it = cache.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void DNSCache::evictLRUEntries() {
    if (cache.empty()) {
        return;
    }
   
    // Find entry with lowest hit count and oldest insertion time
    auto lru_it = cache.begin();
    for (auto it = cache.begin(); it != cache.end(); ++it) {
        if (it->second->hit_count < lru_it->second->hit_count ||
            (it->second->hit_count == lru_it->second->hit_count &&
             it->second->inserted < lru_it->second->inserted)) {
            lru_it = it;
        }
    }
   
    current_memory_usage -= estimateEntrySize(*lru_it->second);
    cache.erase(lru_it);
    cache_evictions++;
}

std::string DNSCache::makeCacheKey(const std::string& name, uint16_t type) const {
    return name + ":" + std::to_string(type);
}

size_t DNSCache::estimateEntrySize(const CacheEntry& entry) const {
    size_t size = sizeof(CacheEntry);
   
    for (const auto& record : entry.records) {
        size += record.name.size() + record.data.size() + sizeof(DNSRecord);
    }
   
    return size;
}

DNSCache::CacheStats DNSCache::getStats() const {
    std::shared_lock<std::shared_mutex> lock(cache_mutex);
   
    CacheStats stats;
    stats.hits = cache_hits.load();
    stats.misses = cache_misses.load();
    stats.evictions = cache_evictions.load();
    stats.entries = cache.size();
    stats.memory_usage_mb = current_memory_usage.load() / (1024 * 1024);
   
    uint64_t total_requests = stats.hits + stats.misses;
    stats.hit_ratio = total_requests > 0 ? 
        static_cast<double>(stats.hits) / total_requests : 0.0;
   
    return stats;
}

void DNSCache::resetStats() {
    cache_hits = 0;
    cache_misses = 0;
    cache_evictions = 0;
}

void DNSCache::setMaxEntries(size_t max_ent) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    max_entries = max_ent;
   
    while (cache.size() > max_entries && !cache.empty()) {
        evictLRUEntries();
    }
}

void DNSCache::setMaxMemory(size_t max_mem) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    max_memory_mb = max_mem;
   
    while (current_memory_usage > max_memory_mb * 1024 * 1024 && !cache.empty()) {
        evictLRUEntries();
    }
}