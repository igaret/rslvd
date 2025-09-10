#include "config/config_manager.h"
#include "monitoring/logger.h"
#include <fstream>
#include <filesystem>

ConfigManager::ConfigManager(const std::string& cfg_file) 
    : config_file(cfg_file), reload_running(true) {
   
    loadConfig();
    reload_thread = std::thread(&ConfigManager::watchConfigFile, this);
}

ConfigManager::~ConfigManager() {
    reload_running = false;
    if (reload_thread.joinable()) {
        reload_thread.join();
    }
}

bool ConfigManager::loadConfig() {
    if (!std::filesystem::exists(config_file)) {
        LOG_WARNING("Config file not found: " + config_file + ", using defaults", "CONFIG");
        return saveConfig(); // Create default config file
    }
   
    return parseConfigFile(config_file);
}

bool ConfigManager::parseConfigFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open config file: " + filename, "CONFIG");
        return false;
    }
   
    std::unique_lock<std::shared_mutex> lock(config_mutex);
    ServerConfig new_config = config; // Start with current config
   
    std::string line;
    int line_number = 0;
   
    while (std::getline(file, line)) {
        line_number++;
        line = trim(line);
       
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
       
        size_t equals_pos = line.find('=');
        if (equals_pos == std::string::npos) {
            LOG_WARNING("Invalid config line " + std::to_string(line_number) + ": " + line, "CONFIG");
            continue;
        }
       
        std::string key = trim(line.substr(0, equals_pos));
        std::string value = trim(line.substr(equals_pos + 1));
       
        // Remove quotes if present
        if (value.length() >= 2 && value[0] == '"' && value.back() == '"') {
            value = value.substr(1, value.length() - 2);
        }
       
        // Parse configuration values
        try {
            if (key == "port") {
                new_config.port = static_cast<uint16_t>(std::stoul(value));
            } else if (key == "bind_address") {
                new_config.bind_address = value;
            } else if (key == "enable_tcp") {
                new_config.enable_tcp = (value == "true" || value == "1");
            } else if (key == "enable_udp") {
                new_config.enable_udp = (value == "true" || value == "1");
            } else if (key == "enable_ipv6") {
                new_config.enable_ipv6 = (value == "true" || value == "1");
            } else if (key == "thread_pool_size") {
                new_config.thread_pool_size = std::stoul(value);
            } else if (key == "max_concurrent_connections") {
                new_config.max_concurrent_connections = std::stoul(value);
            } else if (key == "tcp_timeout_seconds") {
                new_config.tcp_timeout_seconds = std::stoul(value);
            } else if (key == "enable_rate_limiting") {
                new_config.enable_rate_limiting = (value == "true" || value == "1");
            } else if (key == "max_queries_per_second") {
                new_config.max_queries_per_second = std::stoul(value);
            } else if (key == "max_queries_per_minute") {
                new_config.max_queries_per_minute = std::stoul(value);
            } else if (key == "enable_acl") {
                new_config.enable_acl = (value == "true" || value == "1");
            } else if (key == "acl_file") {
                new_config.acl_file = value;
            } else if (key == "enable_cache") {
                new_config.enable_cache = (value == "true" || value == "1");
            } else if (key == "cache_max_entries") {
                new_config.cache_max_entries = std::stoul(value);
            } else if (key == "cache_max_memory_mb") {
                new_config.cache_max_memory_mb = std::stoul(value);
            } else if (key == "log_directory") {
                new_config.log_directory = value;
            } else if (key == "log_level") {
                new_config.log_level = value;
            } else if (key == "log_to_console") {
                new_config.log_to_console = (value == "true" || value == "1");
            } else if (key == "log_to_file") {
                new_config.log_to_file = (value == "true" || value == "1");
            } else if (key == "zones_directory") {
                new_config.zones_directory = value;
            } else if (key == "auto_reload_zones") {
                new_config.auto_reload_zones = (value == "true" || value == "1");
            } else if (key == "enable_ddns") {
                new_config.enable_ddns = (value == "true" || value == "1");
            } else if (key == "ddns_keys_file") {
                new_config.ddns_keys_file = value;
            } else if (key == "enable_metrics") {
                new_config.enable_metrics = (value == "true" || value == "1");
            } else if (key == "metrics_port") {
                new_config.metrics_port = static_cast<uint16_t>(std::stoul(value));
            } else {
                LOG_WARNING("Unknown config key: " + key, "CONFIG");
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Error parsing config value for " + key + ": " + e.what(), "CONFIG");
        }
    }
   
    // Validate configuration
    if (!validateConfig(new_config)) {
        LOG_ERROR("Invalid configuration, keeping current settings", "CONFIG");
        return false;
    }
   
    config = new_config;
   
    // Update last modified time
    try {
        last_modified = std::filesystem::last_write_time(filename);
    } catch (const std::exception& e) {
        LOG_WARNING("Failed to get file modification time: " + std::string(e.what()), "CONFIG");
    }
   
    LOG_INFO("Configuration loaded from " + filename, "CONFIG");
    return true;
}

bool ConfigManager::saveConfig() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex);
   
    try {
        std::filesystem::create_directories(std::filesystem::path(config_file).parent_path());
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create config directory: " + std::string(e.what()), "CONFIG");
        return false;
    }
   
    std::ofstream file(config_file);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open config file for writing: " + config_file, "CONFIG");
        return false;
    }
   
    file << "# RSLVD DNS Configuration File\n";
    file << "# Generated automatically - modify with care\n\n";
   
    file << "# Server settings\n";
    file << "port=" << config.port << "\n";
    file << "bind_address=\"" << config.bind_address << "\"\n";
    file << "enable_tcp=" << (config.enable_tcp ? "true" : "false") << "\n";
    file << "enable_udp=" << (config.enable_udp ? "true" : "false") << "\n";
    file << "enable_ipv6=" << (config.enable_ipv6 ? "true" : "false") << "\n\n";
   
    file << "# Performance settings\n";
    file << "thread_pool_size=" << config.thread_pool_size << "\n";
    file << "max_concurrent_connections=" << config.max_concurrent_connections << "\n";
    file << "tcp_timeout_seconds=" << config.tcp_timeout_seconds << "\n\n";
   
    file << "# Security settings\n";
    file << "enable_rate_limiting=" << (config.enable_rate_limiting ? "true" : "false") << "\n";
    file << "max_queries_per_second=" << config.max_queries_per_second << "\n";
    file << "max_queries_per_minute=" << config.max_queries_per_minute << "\n";
    file << "enable_acl=" << (config.enable_acl ? "true" : "false") << "\n";
    file << "acl_file=\"" << config.acl_file << "\"\n\n";
   
    file << "# Cache settings\n";
    file << "enable_cache=" << (config.enable_cache ? "true" : "false") << "\n";
    file << "cache_max_entries=" << config.cache_max_entries << "\n";
    file << "cache_max_memory_mb=" << config.cache_max_memory_mb << "\n\n";
   
    file << "# Logging settings\n";
    file << "log_directory=\"" << config.log_directory << "\"\n";
    file << "log_level=\"" << config.log_level << "\"\n";
    file << "log_to_console=" << (config.log_to_console ? "true" : "false") << "\n";
    file << "log_to_file=" << (config.log_to_file ? "true" : "false") << "\n\n";
   
    file << "# Zone settings\n";
    file << "zones_directory=\"" << config.zones_directory << "\"\n";
    file << "auto_reload_zones=" << (config.auto_reload_zones ? "true" : "false") << "\n\n";
   
    file << "# DDNS settings\n";
    file << "enable_ddns=" << (config.enable_ddns ? "true" : "false") << "\n";
    file << "ddns_keys_file=\"" << config.ddns_keys_file << "\"\n\n";
   
    file << "# Monitoring settings\n";
    file << "enable_metrics=" << (config.enable_metrics ? "true" : "false") << "\n";
    file << "metrics_port=" << config.metrics_port << "\n";
   
    LOG_INFO("Configuration saved to " + config_file, "CONFIG");
    return true;
}

bool ConfigManager::reloadConfig() {
    return parseConfigFile(config_file);
}

void ConfigManager::watchConfigFile() {
    while (reload_running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
       
        try {
            if (std::filesystem::exists(config_file)) {
                auto current_modified = std::filesystem::last_write_time(config_file);
                if (current_modified > last_modified) {
                    LOG_INFO("Config file changed, reloading...", "CONFIG");
                    reloadConfig();
                }
            }
        } catch (const std::exception& e) {
            // Ignore filesystem errors during watching
        }
    }
}

ServerConfig ConfigManager::getConfig() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex);
    return config;
}

void ConfigManager::updateConfig(const ServerConfig& new_config) {
    if (!validateConfig(new_config)) {
        throw std::invalid_argument("Invalid configuration");
    }
   
    std::unique_lock<std::shared_mutex> lock(config_mutex);
    config = new_config;
}

bool ConfigManager::validateConfig(const ServerConfig& cfg) const {
    return getConfigErrors(cfg).empty();
}

std::vector<std::string> ConfigManager::getConfigErrors(const ServerConfig& cfg) const {
    std::vector<std::string> errors;
   
    if (cfg.port == 0) {
        errors.push_back("Port cannot be 0");
    }
   
    if (!cfg.enable_tcp && !cfg.enable_udp) {
        errors.push_back("At least one of TCP or UDP must be enabled");
    }
   
    if (cfg.thread_pool_size == 0) {
        errors.push_back("Thread pool size must be greater than 0");
    }
   
    if (cfg.max_concurrent_connections == 0) {
        errors.push_back("Max concurrent connections must be greater than 0");
    }
   
    if (cfg.cache_max_entries == 0 && cfg.enable_cache) {
        errors.push_back("Cache max entries must be greater than 0 when cache is enabled");
    }
   
    if (cfg.log_level != "DEBUG" && cfg.log_level != "INFO" && 
        cfg.log_level != "WARNING" && cfg.log_level != "ERROR" && 
        cfg.log_level != "CRITICAL") {
        errors.push_back("Invalid log level: " + cfg.log_level);
    }
   
    return errors;
}

std::string ConfigManager::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
   
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

uint16_t ConfigManager::getPort() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex);
    return config.port;
}

std::string ConfigManager::getBindAddress() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex);
    return config.bind_address;
}

bool ConfigManager::isTCPEnabled() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex);
    return config.enable_tcp;
}

bool ConfigManager::isUDPEnabled() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex);
    return config.enable_udp;
}

bool ConfigManager::isIPv6Enabled() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex);
    return config.enable_ipv6;
}