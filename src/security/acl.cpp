#include "security/acl.h"
#include "monitoring/logger.h"
#include <fstream>
#include <sstream>

AccessControlList::AccessControlList() {
    addDefaultRules();
}

void AccessControlList::addRule(const std::string& network, uint32_t prefix_length,
                               ACLAction action, const std::string& description) {
    std::unique_lock<std::shared_mutex> lock(acl_mutex);
   
    ACLRule rule(network, prefix_length, action, description);
   
    if (isValidIPv4(network)) {
        ipv4_rules.push_back(rule);
    } else if (isValidIPv6(network)) {
        ipv6_rules.push_back(rule);
    } else {
        LOG_ERROR("Invalid network address: " + network, "ACL");
    }
}

void AccessControlList::removeRule(const std::string& network, uint32_t prefix_length) {
    std::unique_lock<std::shared_mutex> lock(acl_mutex);
   
    auto remove_pred = [&](const ACLRule& rule) {
        return rule.network == network && rule.prefix_length == prefix_length;
    };
   
    ipv4_rules.erase(std::remove_if(ipv4_rules.begin(), ipv4_rules.end(), remove_pred),
                     ipv4_rules.end());
   
    ipv6_rules.erase(std::remove_if(ipv6_rules.begin(), ipv6_rules.end(), remove_pred),
                     ipv6_rules.end());
}

void AccessControlList::clearRules() {
    std::unique_lock<std::shared_mutex> lock(acl_mutex);
    ipv4_rules.clear();
    ipv6_rules.clear();
}

ACLAction AccessControlList::checkAccess(const std::string& client_ip) const {
    std::shared_lock<std::shared_mutex> lock(acl_mutex);
   
    if (isValidIPv4(client_ip)) {
        for (const auto& rule : ipv4_rules) {
            if (matchesIPv4Rule(client_ip, rule)) {
                return rule.action;
            }
        }
    } else if (isValidIPv6(client_ip)) {
        for (const auto& rule : ipv6_rules) {
            if (matchesIPv6Rule(client_ip, rule)) {
                return rule.action;
            }
        }
    }
   
    // Default action if no rules match
    return ACLAction::ALLOW;
}

bool AccessControlList::matchesIPv4Rule(const std::string& ip, const ACLRule& rule) const {
    struct sockaddr_in client_addr, network_addr;
   
    if (inet_pton(AF_INET, ip.c_str(), &client_addr.sin_addr) != 1 ||
        inet_pton(AF_INET, rule.network.c_str(), &network_addr.sin_addr) != 1) {
        return false;
    }
   
    uint32_t mask = 0xFFFFFFFF << (32 - rule.prefix_length);
    uint32_t client_net = ntohl(client_addr.sin_addr.s_addr) & mask;
    uint32_t rule_net = ntohl(network_addr.sin_addr.s_addr) & mask;
   
    return client_net == rule_net;
}

bool AccessControlList::matchesIPv6Rule(const std::string& ip, const ACLRule& rule) const {
    struct sockaddr_in6 client_addr, network_addr;
   
    if (inet_pton(AF_INET6, ip.c_str(), &client_addr.sin6_addr) != 1 ||
        inet_pton(AF_INET6, rule.network.c_str(), &network_addr.sin6_addr) != 1) {
        return false;
    }
   
    // IPv6 prefix matching
    uint32_t bytes_to_check = rule.prefix_length / 8;
    uint32_t bits_in_last_byte = rule.prefix_length % 8;
   
    // Check full bytes
    if (memcmp(&client_addr.sin6_addr, &network_addr.sin6_addr, bytes_to_check) != 0) {
        return false;
    }
   
    // Check remaining bits in the last byte
    if (bits_in_last_byte > 0 && bytes_to_check < 16) {
        uint8_t mask = 0xFF << (8 - bits_in_last_byte);
        uint8_t client_byte = ((uint8_t*)&client_addr.sin6_addr)[bytes_to_check];
        uint8_t network_byte = ((uint8_t*)&network_addr.sin6_addr)[bytes_to_check];
       
        if ((client_byte & mask) != (network_byte & mask)) {
            return false;
        }
    }
   
    return true;
}

bool AccessControlList::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open ACL file: " + filename, "ACL");
        return false;
    }
   
    clearRules();
   
    std::string line;
    int line_number = 0;
   
    while (std::getline(file, line)) {
        line_number++;
       
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
       
        std::istringstream iss(line);
        std::string network, action_str, description;
       
        if (!(iss >> network >> action_str)) {
            LOG_WARNING("Invalid ACL rule at line " + std::to_string(line_number), "ACL");
            continue;
        }
       
        // Parse network/prefix
        size_t slash_pos = network.find('/');
        if (slash_pos == std::string::npos) {
            LOG_WARNING("Missing prefix length at line " + std::to_string(line_number), "ACL");
            continue;
        }
       
        std::string net_addr = network.substr(0, slash_pos);
        uint32_t prefix_length = std::stoul(network.substr(slash_pos + 1));
       
        // Parse action
        ACLAction action;
        if (action_str == "allow") {
            action = ACLAction::ALLOW;
        } else if (action_str == "deny") {
            action = ACLAction::DENY;
        } else if (action_str == "require_auth") {
            action = ACLAction::REQUIRE_AUTH;
        } else {
            LOG_WARNING("Invalid action '" + action_str + "' at line " + std::to_string(line_number), "ACL");
            continue;
        }
       
        // Get description (rest of line)
        std::getline(iss, description);
        if (!description.empty() && description[0] == ' ') {
            description = description.substr(1);
        }
       
        addRule(net_addr, prefix_length, action, description);
    }
   
    LOG_INFO("Loaded ACL rules from " + filename, "ACL");
    return true;
}

bool AccessControlList::saveToFile(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open ACL file for writing: " + filename, "ACL");
        return false;
    }
   
    file << "# RSLVD DNS Access Control List\n";
    file << "# Format: network/prefix action [description]\n";
    file << "# Actions: allow, deny, require_auth\n\n";
   
    std::shared_lock<std::shared_mutex> lock(acl_mutex);
   
    for (const auto& rule : ipv4_rules) {
        file << rule.network << "/" << rule.prefix_length << " ";
       
        switch (rule.action) {
            case ACLAction::ALLOW: file << "allow"; break;
            case ACLAction::DENY: file << "deny"; break;
            case ACLAction::REQUIRE_AUTH: file << "require_auth"; break;
        }
       
        if (!rule.description.empty()) {
            file << " " << rule.description;
        }
        file << "\n";
    }
   
    for (const auto& rule : ipv6_rules) {
        file << rule.network << "/" << rule.prefix_length << " ";
       
        switch (rule.action) {
            case ACLAction::ALLOW: file << "allow"; break;
            case ACLAction::DENY: file << "deny"; break;
            case ACLAction::REQUIRE_AUTH: file << "require_auth"; break;
        }
       
        if (!rule.description.empty()) {
            file << " " << rule.description;
        }
        file << "\n";
    }
   
    return true;
}

std::vector<ACLRule> AccessControlList::getRules() const {
    std::shared_lock<std::shared_mutex> lock(acl_mutex);
   
    std::vector<ACLRule> all_rules;
    all_rules.insert(all_rules.end(), ipv4_rules.begin(), ipv4_rules.end());
    all_rules.insert(all_rules.end(), ipv6_rules.begin(), ipv6_rules.end());
   
    return all_rules;
}

void AccessControlList::addDefaultRules() {
    // Allow localhost
    addRule("127.0.0.0", 8, ACLAction::ALLOW, "Localhost IPv4");
    addRule("::1", 128, ACLAction::ALLOW, "Localhost IPv6");
   
    // Allow private networks
    addRule("10.0.0.0", 8, ACLAction::ALLOW, "Private network 10.x.x.x");
    addRule("172.16.0.0", 12, ACLAction::ALLOW, "Private network 172.16-31.x.x");
    addRule("192.168.0.0", 16, ACLAction::ALLOW, "Private network 192.168.x.x");
    addRule("fc00::", 7, ACLAction::ALLOW, "Private IPv6 networks");
}

void AccessControlList::addLocalNetworkRules() {
    addRule("169.254.0.0", 16, ACLAction::ALLOW, "Link-local IPv4");
    addRule("fe80::", 10, ACLAction::ALLOW, "Link-local IPv6");
}

void AccessControlList::addCloudflareRules() {
    addRule("1.1.1.0", 24, ACLAction::ALLOW, "Cloudflare DNS");
    addRule("1.0.0.0", 24, ACLAction::ALLOW, "Cloudflare DNS");
    addRule("2606:4700:4700::", 48, ACLAction::ALLOW, "Cloudflare DNS IPv6");
}

void AccessControlList::addGoogleDNSRules() {
    addRule("8.8.8.0", 24, ACLAction::ALLOW, "Google DNS");
    addRule("8.8.4.0", 24, ACLAction::ALLOW, "Google DNS");
    addRule("2001:4860:4860::", 48, ACLAction::ALLOW, "Google DNS IPv6");
}
