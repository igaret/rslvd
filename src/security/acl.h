#pragma once
#include "utils/utils.h"

enum class ACLAction {
    ALLOW,
    DENY,
    REQUIRE_AUTH
};

struct ACLRule {
    std::string network;
    uint32_t prefix_length;
    ACLAction action;
    std::string description;
   
    ACLRule(const std::string& net, uint32_t prefix, ACLAction act, const std::string& desc = "")
        : network(net), prefix_length(prefix), action(act), description(desc) {}
};

class AccessControlList {
private:
    std::vector<ACLRule> ipv4_rules;
    std::vector<ACLRule> ipv6_rules;
    mutable std::shared_mutex acl_mutex;
   
    bool matchesIPv4Rule(const std::string& ip, const ACLRule& rule) const;
    bool matchesIPv6Rule(const std::string& ip, const ACLRule& rule) const;
   
public:
    AccessControlList();
   
    void addRule(const std::string& network, uint32_t prefix_length, 
                 ACLAction action, const std::string& description = "");
    void removeRule(const std::string& network, uint32_t prefix_length);
    void clearRules();
   
    ACLAction checkAccess(const std::string& client_ip) const;
   
    bool loadFromFile(const std::string& filename);
    bool saveToFile(const std::string& filename) const;
   
    std::vector<ACLRule> getRules() const;
   
    // Default rules for common scenarios
    void addDefaultRules();
    void addLocalNetworkRules();
    void addCloudflareRules();
    void addGoogleDNSRules();
};
