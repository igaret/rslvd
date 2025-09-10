#include "utils/crypto_utils.h"
#include "monitoring/logger.h"

std::vector<uint8_t> CryptoUtils::computeHMAC_SHA256(const std::vector<uint8_t>& key,
                                                     const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    unsigned int result_len;
   
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         data.data(), data.size(), result.data(), &result_len);
   
    result.resize(result_len);
    return result;
}

std::vector<uint8_t> CryptoUtils::computeHMAC_SHA1(const std::vector<uint8_t>& key,
                                                   const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(SHA_DIGEST_LENGTH);
    unsigned int result_len;
   
    HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()),
         data.data(), data.size(), result.data(), &result_len);
   
    result.resize(result_len);
    return result;
}

std::vector<uint8_t> CryptoUtils::computeHMAC_MD5(const std::vector<uint8_t>& key,
                                                  const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(MD5_DIGEST_LENGTH);
    unsigned int result_len;
   
    HMAC(EVP_md5(), key.data(), static_cast<int>(key.size()),
         data.data(), data.size(), result.data(), &result_len);
   
    result.resize(result_len);
    return result;
}

std::vector<uint8_t> CryptoUtils::computeSHA256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), result.data());
    return result;
}

std::vector<uint8_t> CryptoUtils::generateRandomBytes(size_t length) {
    std::vector<uint8_t> result(length);
   
    if (RAND_bytes(result.data(), static_cast<int>(length)) != 1) {
        LOG_ERROR("Failed to generate random bytes", "CRYPTO");
        // Fallback to system random
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
       
        for (size_t i = 0; i < length; ++i) {
            result[i] = static_cast<uint8_t>(dis(gen));
        }
    }
   
    return result;
}

std::string CryptoUtils::generateRandomString(size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charset_size = sizeof(charset) - 1;
   
    auto random_bytes = generateRandomBytes(length);
    std::string result;
    result.reserve(length);
   
    for (uint8_t byte : random_bytes) {
        result += charset[byte % charset_size];
    }
   
    return result;
}

std::string CryptoUtils::base64Encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
   
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
   
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
   
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
   
    return result;
}

std::vector<uint8_t> CryptoUtils::base64Decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.length()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
   
    std::vector<uint8_t> result(encoded.length());
    int decoded_length = BIO_read(bio, result.data(), static_cast<int>(result.size()));
   
    BIO_free_all(bio);
   
    if (decoded_length > 0) {
        result.resize(decoded_length);
    } else {
        result.clear();
    }
   
    return result;
}

std::string CryptoUtils::hexEncode(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
   
    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
   
    return oss.str();
}

std::vector<uint8_t> CryptoUtils::hexDecode(const std::string& hex) {
    std::vector<uint8_t> result;
   
    if (hex.length() % 2 != 0) {
        return result; // Invalid hex string
    }
   
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        result.push_back(byte);
    }
   
    return result;
}

bool CryptoUtils::secureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
   
    int result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= a[i] ^ b[i];
    }
   
    return result == 0;
}

std::vector<uint8_t> CryptoUtils::deriveKey(const std::string& password,
                                           const std::vector<uint8_t>& salt,
                                           int iterations, size_t key_length) {
    std::vector<uint8_t> result(key_length);
   
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                         salt.data(), static_cast<int>(salt.size()),
                         iterations, EVP_sha256(),
                         static_cast<int>(key_length), result.data()) != 1) {
        LOG_ERROR("Key derivation failed", "CRYPTO");
        result.clear();
    }
   
    return result;
}