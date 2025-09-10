#pragma once
#include "utils/utils.h"
#include "dns_packet.h"
#include "dns_record.h"
#include "cache/dns_cache.h"
#include "security/rate_limiter.h"
#include "security/acl.h"
#include "security/auth_manager.h"
#include "monitoring/logger.h"
#include "monitoring/metrics.h"
#include "config/config_manager.h"
#include "utils/thread_pool.h"

class rslvd {
private:
    // Core components
    std::unique_ptr<ConfigManager> config_manager;
    std::unique_ptr<ThreadPool> thread_pool;
    std::unique_ptr<DNSCache> dns_cache;
    std::unique_ptr<RateLimiter> rate_limiter;
    std::unique_ptr<AccessControlList> acl;
    std::unique_ptr<AuthenticationManager> auth_manager;
    std::unique_ptr<MetricsCollector> metrics;
   
    // Network sockets
    SOCKET udp_socket_v4;
    SOCKET udp_socket_v6;
    SOCKET tcp_socket_v4;
    SOCKET tcp_socket_v6;
   
    // Server state
    std::atomic<bool> running;
    std::atomic<bool> shutdown_requested;
   
    // Zone data
    std::map<std::string, std::vector<DNSRecord>> zones;
    mutable std::shared_mutex zones_mutex;
    std::thread zone_reload_thread;
   
    // Network threads
    std::vector<std::thread> network_threads;
   
    // Statistics
    std::atomic<uint64_t> total_queries;
    std::atomic<uint64_t> total_responses;
    std::atomic<uint64_t> failed_queries;
    std::atomic<uint64_t> cache_hits;
    std::atomic<uint64_t> cache_misses;
   
    // Network initialization
    NetworkInitializer network_init;
   
    // Private methods
    bool initializeSockets();
    void cleanupSockets();
    bool bindSocket(SOCKET sock, const std::string& address, uint16_t port, bool ipv6);
   
    // Network handlers
    void handleUDPRequests(SOCKET socket, bool ipv6);
    void handleTCPRequests(SOCKET socket, bool ipv6);
    void handleTCPConnection(SOCKET client_socket, const std::string& client_ip);
   
    // DNS processing
    void processQuery(const std::vector<uint8_t>& request_data, 
                     const std::string& client_ip, uint16_t client_port,
                     SOCKET response_socket, struct sockaddr* client_addr, 
                     socklen_t addr_len, bool is_tcp);
   
    std::vector<uint8_t> createResponse(const DNSPacket& request, 
                                       const std::string& client_ip);
   
    std::vector<DNSRecord> lookupRecords(const std::string& name, uint16_t type);
    std::vector<DNSRecord> lookupInZones(const std::string& name, uint16_t type);
    std::vector<DNSRecord> lookupInCache(const std::string& name, uint16_t type);
   
    // DDNS handling
    bool handleDDNSUpdate(const DNSPacket& request, const std::string& client_ip);
    bool validateDDNSAuth(const DNSPacket& request, const std::string& client_ip);
   
    // Zone management
    void loadZones();
    void reloadZones();
    void watchZoneFiles();
    bool loadZoneFile(const std::string& filename);
   
    // Utility methods
    std::string getClientIP(struct sockaddr* addr, socklen_t addr_len);
    bool isAuthoritative(const std::string& name);
    uint16_t generateTransactionId();
   
    // Signal handling
    static void signalHandler(int signal);
    static rslvd* instance;
   
public:
    rslvd();
    ~rslvd();
   
    bool initialize(const std::string& config_file = "config/rslvd.conf");
    bool start();
    void stop();
    void shutdown();
   
    // Configuration
    bool reloadConfiguration();
    ServerConfig getConfiguration() const;
   
    // Zone management
    bool addZone(const std::string& zone_name, const std::vector<DNSRecord>& records);
    bool removeZone(const std::string& zone_name);
    std::vector<std::string> getZones() const;
   
    // Statistics
    struct ServerStats {
        uint64_t total_queries;
        uint64_t total_responses;
        uint64_t failed_queries;
        uint64_t cache_hits;
        uint64_t cache_misses;
        uint32_t active_connections;
        uint32_t zones_loaded;
        std::chrono::steady_clock::time_point start_time;
        double uptime_seconds;
    };
   
    ServerStats getStats() const;
    void resetStats();
   
    // Health check
    bool isHealthy() const;
    std::string getHealthStatus() const;
};
