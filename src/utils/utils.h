#pragma once

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    typedef int socklen_t;
    #define CLOSE_SOCKET closesocket
    #define GET_SOCKET_ERROR() WSAGetLastError()
#else
    #include <sys/socket.h>
    #include <sys/epoll.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define CLOSE_SOCKET close
    #define GET_SOCKET_ERROR() errno
#endif

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <queue>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <regex>
#include <cstring>
#include <csignal>

// DNS Constants
#define DNS_PORT 53
#define MAX_DNS_PACKET_SIZE 512
#define MAX_TCP_DNS_PACKET_SIZE 65535
#define DNS_HEADER_SIZE 12
#define MAX_DOMAIN_NAME_LENGTH 253
#define MAX_LABEL_LENGTH 63

// DNS Types
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_SRV 33
#define DNS_TYPE_NAPTR 35
#define DNS_TYPE_DNSKEY 48
#define DNS_TYPE_RRSIG 46
#define DNS_TYPE_NSEC 47

// DNS Classes
#define DNS_CLASS_IN 1
#define DNS_CLASS_CH 3
#define DNS_CLASS_HS 4

// DNS Response Codes
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5
#define DNS_RCODE_YXDOMAIN 6
#define DNS_RCODE_YXRRSET 7
#define DNS_RCODE_NXRRSET 8
#define DNS_RCODE_NOTAUTH 9
#define DNS_RCODE_NOTZONE 10

// Security constants
#define MAX_QUERIES_PER_SECOND 100
#define MAX_QUERIES_PER_MINUTE 1000
#define MAX_CONCURRENT_CONNECTIONS 1000
#define DDNS_KEY_SIZE 32
#define HMAC_SIGNATURE_SIZE 32

class NetworkInitializer {
public:
    NetworkInitializer() {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
    }
   
    ~NetworkInitializer() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

// Utility functions
std::string getCurrentTimestamp();
std::string generateRandomString(size_t length);
bool isValidDomainName(const std::string& domain);
bool isValidIPv4(const std::string& ip);
bool isValidIPv6(const std::string& ip);
std::string sanitizeString(const std::string& input);
uint32_t calculateChecksum(const void* data, size_t length);