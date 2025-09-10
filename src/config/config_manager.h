#pragma once
#include "utils/utils.h"

struct ServerConfig {
    uint16_t port = DNS_PORT;
    std::string bind_address = "0.0.0.0";
    bool enable_tcp = true;
    bool enable_udp = true;
    bool enable_ipv6 = true;
   
    // Performance settings
    size_t thread_pool_size = std::thread::hardware_concurrency();
    size_t max_concurrent_connections = MAX_CONCURRENT_CONNECTIONS;
    size_t tcp_timeout_seconds = 30;
    size_t udp_buffer_size = MAX_DNS_PACKET_SIZE;
    size_t tcp_buffer_size = MAX_TCP_DNS_PACKET_SIZE;
   
    // Security settings
    bool enable_rate_limiting = true;
    uint32_t max_queries_per_second = MAX_QUERIES_PER_SECOND;
    uint32_t max_queries_per_minute = MAX_QUERIES_PER_MINUTE;
    bool enable_acl = true;
    std::string acl_file = "config/acl.conf";
   
    // Cache settings
    bool enable_cache = true;
    size_t cache_max_entries = 10000;
    size_t cache_max_memory_mb = 100;
   
    // Logging settings
    std::string log_directory = "logs";
    std::string log_level = "INFO";
    bool log_to_console = true;
    bool log_to_file = true;
    size_t log_max_file_size_mb = 100;
    size_t log_max_files = 10;
   
    // Zone settings
    std::string zones_directory = "config/zones";
    bool auto_reload_zones = true;
    size_t zone_reload_interval_seconds = 300;
   
    // DDNS settings
    bool enable_ddns = true;
    std::string ddns_keys_file = "config/keys/ddns.keys";
    bool require_auth_for_updates = true;
   
    // Monitoring settings
    bool enable_metrics = true;
    uint16_t metrics_port = 8080;
    std::string metrics_bind_address = "127.0.0.1";
};

class ConfigManager {
private:
    ServerConfig config;
    std::string config_file;
    mutable std::shared_mutex config_mutex;
   
    std::thread reload_thread;
    std::atomic<bool> reload_running;
    std::chrono::system_clock::time_point last_modified;
   
    void watchConfigFile();
    bool parseConfigFile(const std::string& filename);
    std::string trim(const std::string& str);
   
public:
    ConfigManager(const std::string& config_file = "config/rslvd.conf");
    ~ConfigManager();
   
    bool loadConfig();
    bool saveConfig() const;
    bool reloadConfig();
   
    ServerConfig getConfig() const;
    void updateConfig(const ServerConfig& new_config);
   
    // Individual setting getters
    uint16_t getPort() const;
    std::string getBindAddress() const;
    bool isTCPEnabled() const;
    bool isUDPEnabled() const;
    bool isIPv6Enabled() const;
   
    // Validation
    bool validateConfig(const ServerConfig& cfg) const;
    std::vector<std::string> getConfigErrors(const ServerConfig& cfg) const;
};
