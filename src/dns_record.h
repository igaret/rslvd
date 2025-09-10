#pragma once
#include "utils.h"

struct DNSRecord {
    std::string name;
    uint16_t type;
    uint16_t class_code;
    uint32_t ttl;
    std::vector<uint8_t> data;
    
    DNSRecord() : type(0), class_code(DNS_CLASS_IN), ttl(3600) {}
    
    DNSRecord(const std::string& n, uint16_t t, uint32_t time_to_live, 
              const std::vector<uint8_t>& d)
        : name(n), type(t), class_code(DNS_CLASS_IN), ttl(time_to_live), data(d) {}
    
    // Helper methods for common record types
    static DNSRecord createARecord(const std::string& name, const std::string& ip, uint32_t ttl = 3600);
    static DNSRecord createAAAARecord(const std::string& name, const std::string& ipv6, uint32_t ttl = 3600);
    static DNSRecord createCNAMERecord(const std::string& name, const std::string& target, uint32_t ttl = 3600);
    static DNSRecord createMXRecord(const std::string& name, uint16_t priority, const std::string& exchange, uint32_t ttl = 3600);
    static DNSRecord createTXTRecord(const std::string& name, const std::string& text, uint32_t ttl = 3600);
    
    std::string toString() const;
};

class DNSZone {
private:
    std::string zone_name;
    std::map<std::string, std::vector<DNSRecord>> records;
    mutable std::mutex zone_mutex;
    
public:
    DNSZone(const std::string& name) : zone_name(name) {}
    
    void addRecord(const DNSRecord& record);
    void removeRecord(const std::string& name, uint16_t type);
    std::vector<DNSRecord> getRecords(const std::string& name, uint16_t type) const;
    std::vector<DNSRecord> getAllRecords(const std::string& name) const;
    
    bool loadFromFile(const std::string& filename);
    bool saveToFile(const std::string& filename) const;
    
    const std::string& getName() const { return zone_name; }
};
