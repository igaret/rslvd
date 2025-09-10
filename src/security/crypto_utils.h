#pragma once
#include "utils/utils.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

class CryptoUtils {
public:
    // HMAC operations
    static std::vector<uint8_t> computeHMAC_SHA256(const std::vector<uint8_t>& key,
                                                   const std::vector<uint8_t>& data);
    static std::vector<uint8_t> computeHMAC_SHA1(const std::vector<uint8_t>& key,
                                                 const std::vector<uint8_t>& data);
    static std::vector<uint8_t> computeHMAC_MD5(const std::vector<uint8_t>& key,
                                                const std::vector<uint8_t>& data);
   
    // Hash operations
    static std::vector<uint8_t> computeSHA256(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> computeSHA1(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> computeMD5(const std::vector<uint8_t>& data);
   
    // Random generation
    static std::vector<uint8_t> generateRandomBytes(size_t length);
    static std::string generateRandomString(size_t length);
   
    // Base64 encoding/decoding
    static std::string base64Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64Decode(const std::string& encoded);
   
    // Hex encoding/decoding
    static std::string hexEncode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> hexDecode(const std::string& hex);
   
    // Secure comparison
    static bool secureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
   
    // Key derivation
    static std::vector<uint8_t> deriveKey(const std::string& password, 
                                         const std::vector<uint8_t>& salt,
                                         int iterations, size_t key_length);
};