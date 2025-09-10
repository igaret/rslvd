#pragma once
#include "utils.h"
#include "dns_record.h"

#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct DNSQuestion {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;
};
#pragma pack(pop)

class DNSPacket {
private:
    DNSHeader header;
    std::vector<DNSQuestion> questions;
    std::vector<DNSRecord> answers;
    std::vector<DNSRecord> authorities;
    std::vector<DNSRecord> additionals;
    
    static std::string decodeDomainName(const uint8_t* data, size_t& offset, size_t packet_size);
    static size_t encodeDomainName(const std::string& domain, uint8_t* buffer, size_t offset);
    static size_t encodeRecord(const DNSRecord& record, uint8_t* buffer, size_t offset);
    
public:
    DNSPacket();
    
    // Parsing and serialization
    bool parseFromBuffer(const uint8_t* buffer, size_t size);
    size_t serializeToBuffer(uint8_t* buffer, size_t buffer_size) const;
    
    // Header manipulation
    void setId(uint16_t id) { header.id = id; }
    uint16_t getId() const { return header.id; }
    
    void setResponse(bool is_response);
    bool isResponse() const;
    
    void setOpcode(uint8_t opcode);
    uint8_t getOpcode() const;
    
    void setRcode(uint8_t rcode);
    uint8_t getRcode() const;
    
    void setRecursionDesired(bool rd);
    bool isRecursionDesired() const;
    
    void setRecursionAvailable(bool ra);
    bool isRecursionAvailable() const;
    
    // Question manipulation
    void addQuestion(const std::string& qname, uint16_t qtype, uint16_t qclass = DNS_CLASS_IN);
    const std::vector<DNSQuestion>& getQuestions() const { return questions; }
    
    // Answer manipulation
    void addAnswer(const DNSRecord& record);
    void addAuthority(const DNSRecord& record);
    void addAdditional(const DNSRecord& record);
    
    const std::vector<DNSRecord>& getAnswers() const { return answers; }
    const std::vector<DNSRecord>& getAuthorities() const { return authorities; }
    const std::vector<DNSRecord>& getAdditionals() const { return additionals; }
    
    void clear();
    std::string toString() const;
};
