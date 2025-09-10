#pragma once
#include "utils/utils.h"
#include "utils/crypto_utils.h"

struct DDNSKey {
    std::string name;
    std::string algorithm;
    std::vector<uint8_t> key_data;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point expires;
    bool active;
   
    DDNSKey(const std::string& n, const std::string& algo, 
            const std::vector<uint8_t>& data)
        : name(n), algorithm(algo), key_data(data), 
          created(std::chrono::system_clock::now()),
          expires(std::chrono::system_clock::now() + std::chrono::hours(24 * 365)),
          active(true) {}
};

struct AuthSession {
    std::string session_id;
    std::string client_ip;
    std::string key_name;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point last_used;
    bool active;
   
    AuthSession(const std::string& id, const std::string& ip, const std::string& key)
        : session_id(id), client_ip(ip), key_name(key),
          created(std::chrono::system_clock::now()),
          last_used(std::chrono::system_clock::now()),
          active(true) {}
};

class AuthenticationManager {
private:
    std::map<std::string, std::unique_ptr<DDNSKey>> ddns_keys;
    std::map<std::string, std::unique_ptr<AuthSession>> active_sessions;
    mutable std::shared_mutex auth_mutex;
   
    std::thread cleanup_thread;
    std::atomic<bool> cleanup_running;
   
    void cleanupExpiredSessions();
    std::string generateSessionId();
   
public:
    AuthenticationManager();
    ~AuthenticationManager();
   
    // Key management
    bool addKey(const std::string& name, const std::string& algorithm, 
                const std::vector<uint8_t>& key_data);
    bool removeKey(const std::string& name);
    bool loadKeysFromFile(const std::string& filename);
    bool saveKeysToFile(const std::string& filename) const;
   
    // Authentication
    bool authenticateHMAC(const std::string& key_name, const std::vector<uint8_t>& data,
                         const std::vector<uint8_t>& signature);
    std::string createSession(const std::string& client_ip, const std::string& key_name);
    bool validateSession(const std::string& session_id, const std::string& client_ip);
    void invalidateSession(const std::string& session_id);
   
    // TSIG support for DNS updates
    bool validateTSIG(const std::vector<uint8_t>& packet, const std::string& key_name,
                     const std::vector<uint8_t>& mac, uint64_t time_signed);
    std::vector<uint8_t> generateTSIG(const std::vector<uint8_t>& packet, 
                                     const std::string& key_name, uint64_t time_signed);
   
    // Statistics
    struct AuthStats {
        uint32_t total_keys;
        uint32_t active_sessions;
        uint32_t successful_auths;
        uint32_t failed_auths;
    };
   
    AuthStats getStats() const;
    void resetStats();
};