#include "dns_record.h"

DNSRecord DNSRecord::createARecord(const std::string& name, const std::string& ip, uint32_t ttl) {
    std::vector<uint8_t> data(4);
    struct sockaddr_in sa;
    
    if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) {
        memcpy(data.data(), &sa.sin_addr, 4);
    }
    
    return DNSRecord(name, DNS_TYPE_A, ttl, data);
}

DNSRecord DNSRecord::createAAAARecord(const std::string& name, const std::string& ipv6, uint32_t ttl) {
    std::vector<uint8_t> data(16);
    struct sockaddr_in6 sa;
    
    if (inet_pton(AF_INET6, ipv6.c_str(), &(sa.sin6_addr)) == 1) {
        memcpy(data.data(), &sa.sin6_addr, 16);
    }
    
    return DNSRecord(name, DNS_TYPE_AAAA, ttl, data);
}

DNSRecord DNSRecord::createCNAMERecord(const std::string& name, const std::string& target, uint32_t ttl) {
    std::vector<uint8_t> data;
    
    // Encode domain name
    std::istringstream iss(target);
    std::string label;
    
    while (std::getline(iss, label, '.')) {
        data.push_back(static_cast<uint8_t>(label.length()));
        data.insert(data.end(), label.begin(), label.end());
    }
    data.push_back(0); // Root label
    
    return DNSRecord(name, DNS_TYPE_CNAME, ttl, data);
}

DNSRecord DNSRecord::createMXRecord(const std::string& name, uint16_t priority, const std::string& exchange, uint32_t ttl) {
    std::vector<uint8_t> data;
    
    // Add priority (big-endian)
    data.push_back((priority >> 8) & 0xFF);
    data.push_back(priority & 0xFF);
    
    // Add exchange domain name
    std::istringstream iss(exchange);
    std::string label;
    
    while (std::getline(iss, label, '.')) {
        data.push_back(static_cast<uint8_t>(label.length()));
        data.insert(data.end(), label.begin(), label.end());
    }
    data.push_back(0); // Root label
    
    return DNSRecord(name, DNS_TYPE_MX, ttl, data);
}

DNSRecord DNSRecord::createTXTRecord(const std::string& name, const std::string& text, uint32_t ttl) {
    std::vector<uint8_t> data;
    
    // TXT records are length-prefixed strings
    data.push_back(static_cast<uint8_t>(text.length()));
    data.insert(data.end(), text.begin(), text.end());
    
    return DNSRecord(name, DNS_TYPE_TXT, ttl, data);
}

std::string DNSRecord::toString() const {
    std::ostringstream oss;
    oss << name << " " << ttl << " IN ";
    
    switch (type) {
        case DNS_TYPE_A: {
            oss << "A ";
            if (data.size() == 4) {
                oss << static_cast<int>(data[0]) << "." 
                    << static_cast<int>(data[1]) << "." 
                    << static_cast<int>(data[2]) << "." 
                    << static_cast<int>(data[3]);
            }
            break;
        }
        case DNS_TYPE_AAAA: {
            oss << "AAAA ";
            if (data.size() == 16) {
                for (int i = 0; i < 16; i += 2) {
                    if (i > 0) oss << ":";
                    oss << std::hex << (data[i] << 8 | data[i+1]);
                }
            }
            break;
        }
        case DNS_TYPE_CNAME:
            oss << "CNAME ";
            break;
        case DNS_TYPE_MX:
            oss << "MX ";
            break;
        case DNS_TYPE_TXT:
            oss << "TXT ";
            break;
        default:
            oss << "TYPE" << type << " ";
    }
    
    return oss.str();
}

void DNSZone::addRecord(const DNSRecord& record) {
    std::lock_guard<std::mutex> lock(zone_mutex);
    records[record.name].push_back(record);
}

void DNSZone::removeRecord(const std::string& name, uint16_t type) {
    std::lock_guard<std::mutex> lock(zone_mutex);
    
    auto it = records.find(name);
    if (it != records.end()) {
        auto& record_list = it->second;
        record_list.erase(
            std::remove_if(record_list.begin(), record_list.end(),
                [type](const DNSRecord& r) { return r.type == type; }),
            record_list.end()
        );
        
        if (record_list.empty()) {
            records.erase(it);
        }
    }
}

std::vector<DNSRecord> DNSZone::getRecords(const std::string& name, uint16_t type) const {
    std::lock_guard<std::mutex> lock(zone_mutex);
    std::vector<DNSRecord> result;
    
    auto it = records.find(name);
    if (it != records.end()) {
        for (const auto& record : it->second) {
            if (record.type == type) {
                result.push_back(record);
            }
        }
    }
    
    return result;
}

std::vector<DNSRecord> DNSZone::getAllRecords(const std::string& name) const {
    std::lock_guard<std::mutex> lock(zone_mutex);
    
    auto it = records.find(name);
    if (it != records.end()) {
        return it->second;
    }
    
    return {};
}

bool DNSZone::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        std::istringstream iss(line);
        std::string name, ttl_str, class_str, type_str, data_str;
        
        if (iss >> name >> ttl_str >> class_str >> type_str >> data_str) {
            uint32_t ttl = std::stoul(ttl_str);
            
            if (type_str == "A") {
                addRecord(DNSRecord::createARecord(name, data_str, ttl));
            } else if (type_str == "AAAA") {
                addRecord(DNSRecord::createAAAARecord(name, data_str, ttl));
            } else if (type_str == "CNAME") {
                addRecord(DNSRecord::createCNAMERecord(name, data_str, ttl));
            }
            // Add more record types as needed
        }
    }
    
    return true;
}

bool DNSZone::saveToFile(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(zone_mutex);
    
    for (const auto& entry : records) {
        for (const auto& record : entry.second) {
            file << record.toString() << std::endl;
        }
    }
    
    return true;
}
