#include "rslvd.h"
#include <csignal>

rslvd* rslvd::instance = nullptr;

rslvd::rslvd() 
    : udp_socket_v4(INVALID_SOCKET), udp_socket_v6(INVALID_SOCKET),
      tcp_socket_v4(INVALID_SOCKET), tcp_socket_v6(INVALID_SOCKET),
      running(false), shutdown_requested(false),
      total_queries(0), total_responses(0), failed_queries(0),
      cache_hits(0), cache_misses(0) {
   
    instance = this;
   
    // Install signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
#ifndef _WIN32
    std::signal(SIGHUP, signalHandler);
    std::signal(SIGPIPE, SIG_IGN);
#endif
}

rslvd::~rslvd() {
    shutdown();
    instance = nullptr;
}

bool rslvd::initialize(const std::string& config_file) {
    try {
        // Initialize configuration manager
        config_manager = std::make_unique<ConfigManager>(config_file);
        auto config = config_manager->getConfig();
       
        // Initialize logging
        LogLevel log_level = LogLevel::INFO;
        if (config.log_level == "DEBUG") log_level = LogLevel::DEBUG;
        else if (config.log_level == "WARNING") log_level = LogLevel::WARNING;
        else if (config.log_level == "ERROR") log_level = LogLevel::ERROR;
        else if (config.log_level == "CRITICAL") log_level = LogLevel::CRITICAL;
       
        Logger::getInstance().configure(
            config.log_directory, log_level,
            config.log_to_console, config.log_to_file,
            config.log_max_file_size_mb * 1024 * 1024,
            config.log_max_files
        );
       
        LOG_INFO("RSLVD DNS initializing...", "SERVER");
       
        // Initialize thread pool
        thread_pool = std::make_unique<ThreadPool>(config.thread_pool_size);
       
        // Initialize cache
        if (config.enable_cache) {
            dns_cache = std::make_unique<DNSCache>(
                config.cache_max_entries, config.cache_max_memory_mb);
        }
       
        // Initialize rate limiter
        if (config.enable_rate_limiting) {
            rate_limiter = std::make_unique<RateLimiter>(
                config.max_queries_per_second,
                config.max_queries_per_minute,
                config.max_concurrent_connections
            );
        }
       
        // Initialize ACL
        if (config.enable_acl) {
            acl = std::make_unique<AccessControlList>();
            if (!config.acl_file.empty()) {
                acl->loadFromFile(config.acl_file);
            }
        }
       
        // Initialize authentication manager
        if (config.enable_ddns) {
            auth_manager = std::make_unique<AuthenticationManager>();
            if (!config.ddns_keys_file.empty()) {
                auth_manager->loadKeysFromFile(config.ddns_keys_file);
            }
        }
       
        // Initialize metrics collector
        if (config.enable_metrics) {
            metrics = std::make_unique<MetricsCollector>(
                config.metrics_bind_address, config.metrics_port);
        }
       
        // Initialize network sockets
        if (!initializeSockets()) {
            LOG_ERROR("Failed to initialize network sockets", "SERVER");
            return false;
        }
       
        // Load zones
        loadZones();
       
        // Start zone file watcher
        if (config.auto_reload_zones) {
            zone_reload_thread = std::thread(&rslvd::watchZoneFiles, this);
        }
       
        LOG_INFO("RSLVD DNS initialized successfully", "SERVER");
        return true;
       
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to initialize RSLVD DNS: " + std::string(e.what()), "SERVER");
        return false;
    }
}

bool rslvd::initializeSockets() {
    auto config = config_manager->getConfig();
   
    try {
        // Create UDP sockets
        if (config.enable_udp) {
            // IPv4 UDP socket
            udp_socket_v4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (udp_socket_v4 == INVALID_SOCKET) {
                LOG_ERROR("Failed to create IPv4 UDP socket", "NETWORK");
                return false;
            }
           
            if (!bindSocket(udp_socket_v4, config.bind_address, config.port, false)) {
                LOG_ERROR("Failed to bind IPv4 UDP socket", "NETWORK");
                return false;
            }
           
            // IPv6 UDP socket
            if (config.enable_ipv6) {
                udp_socket_v6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
                if (udp_socket_v6 == INVALID_SOCKET) {
                    LOG_WARNING("Failed to create IPv6 UDP socket", "NETWORK");
                } else {
                    int v6only = 1;
                    setsockopt(udp_socket_v6, IPPROTO_IPV6, IPV6_V6ONLY, 
                              reinterpret_cast<const char*>(&v6only), sizeof(v6only));
                   
                    if (!bindSocket(udp_socket_v6, "::", config.port, true)) {
                        LOG_WARNING("Failed to bind IPv6 UDP socket", "NETWORK");
                        CLOSE_SOCKET(udp_socket_v6);
                        udp_socket_v6 = INVALID_SOCKET;
                    }
                }
            }
        }
       
        // Create TCP sockets
        if (config.enable_tcp) {
            // IPv4 TCP socket
            tcp_socket_v4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (tcp_socket_v4 == INVALID_SOCKET) {
                LOG_ERROR("Failed to create IPv4 TCP socket", "NETWORK");
                return false;
            }
           
            int reuse = 1;
            setsockopt(tcp_socket_v4, SOL_SOCKET, SO_REUSEADDR, 
                      reinterpret_cast<const char*>(&reuse), sizeof(reuse));
           
            if (!bindSocket(tcp_socket_v4, config.bind_address, config.port, false)) {
                LOG_ERROR("Failed to bind IPv4 TCP socket", "NETWORK");
                return false;
            }
           
            if (listen(tcp_socket_v4, SOMAXCONN) == SOCKET_ERROR) {
                LOG_ERROR("Failed to listen on IPv4 TCP socket", "NETWORK");
                return false;
            }
           
            // IPv6 TCP socket
            if (config.enable_ipv6) {
                tcp_socket_v6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
                if (tcp_socket_v6 == INVALID_SOCKET) {
                    LOG_WARNING("Failed to create IPv6 TCP socket", "NETWORK");
                } else {
                    int v6only = 1;
                    setsockopt(tcp_socket_v6, IPPROTO_IPV6, IPV6_V6ONLY, 
                              reinterpret_cast<const char*>(&v6only), sizeof(v6only));
                    setsockopt(tcp_socket_v6, SOL_SOCKET, SO_REUSEADDR, 
                              reinterpret_cast<const char*>(&reuse), sizeof(reuse));
                   
                    if (!bindSocket(tcp_socket_v6, "::", config.port, true)) {
                        LOG_WARNING("Failed to bind IPv6 TCP socket", "NETWORK");
                        CLOSE_SOCKET(tcp_socket_v6);
                        tcp_socket_v6 = INVALID_SOCKET;
                    } else if (listen(tcp_socket_v6, SOMAXCONN) == SOCKET_ERROR) {
                        LOG_WARNING("Failed to listen on IPv6 TCP socket", "NETWORK");
                        CLOSE_SOCKET(tcp_socket_v6);
                        tcp_socket_v6 = INVALID_SOCKET;
                    }
                }
            }
        }
       
        return true;
       
    } catch (const std::exception& e) {
        LOG_ERROR("Exception during socket initialization: " + std::string(e.what()), "NETWORK");
        cleanupSockets();
        return false;
    }
}

bool rslvd::bindSocket(SOCKET sock, const std::string& address, uint16_t port, bool ipv6) {
    if (ipv6) {
        struct sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
       
        if (address == "::" || address.empty()) {
            addr.sin6_addr = in6addr_any;
        } else {
            if (inet_pton(AF_INET6, address.c_str(), &addr.sin6_addr) != 1) {
                LOG_ERROR("Invalid IPv6 address: " + address, "NETWORK");
                return false;
            }
        }
       
        return bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != SOCKET_ERROR;
    } else {
        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
       
        if (address == "0.0.0.0" || address.empty()) {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
                LOG_ERROR("Invalid IPv4 address: " + address, "NETWORK");
                return false;
            }
        }
       
        return bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != SOCKET_ERROR;
    }
}

bool rslvd::start() {
    if (running.load()) {
        LOG_WARNING("RSLVD DNS is already running", "SERVER");
        return false;
    }
   
    running = true;
    auto config = config_manager->getConfig();
   
    LOG_INFO("Starting RSLVD DNS on port " + std::to_string(config.port), "SERVER");
   
    try {
        // Start UDP handlers
        if (config.enable_udp) {
            if (udp_socket_v4 != INVALID_SOCKET) {
                network_threads.emplace_back(&rslvd::handleUDPRequests, this, udp_socket_v4, false);
            }
            if (udp_socket_v6 != INVALID_SOCKET) {
                network_threads.emplace_back(&rslvd::handleUDPRequests, this, udp_socket_v6, true);
            }
        }
       
        // Start TCP handlers
        if (config.enable_tcp) {
            if (tcp_socket_v4 != INVALID_SOCKET) {
                network_threads.emplace_back(&rslvd::handleTCPRequests, this, tcp_socket_v4, false);
            }
            if (tcp_socket_v6 != INVALID_SOCKET) {
                network_threads.emplace_back(&rslvd::handleTCPRequests, this, tcp_socket_v6, true);
            }
        }
       
        // Start metrics server
        if (metrics) {
            metrics->start();
        }
       
        LOG_INFO("RSLVD DNS started successfully", "SERVER");
        return true;
       
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to start RSLVD DNS: " + std::string(e.what()), "SERVER");
        stop();
        return false;
    }
}

void rslvd::handleUDPRequests(SOCKET socket, bool ipv6) {
    std::vector<uint8_t> buffer(MAX_DNS_PACKET_SIZE);
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
   
    LOG_INFO("UDP handler started for " + std::string(ipv6 ? "IPv6" : "IPv4"), "NETWORK");
   
    while (running.load()) {
        addr_len = sizeof(client_addr);
       
        int bytes_received = recvfrom(socket, reinterpret_cast<char*>(buffer.data()), 
                                     buffer.size(), 0, 
                                     reinterpret_cast<struct sockaddr*>(&client_addr), 
                                     &addr_len);
       
        if (bytes_received == SOCKET_ERROR) {
            if (running.load()) {
                LOG_ERROR("UDP recvfrom error: " + std::to_string(GET_SOCKET_ERROR()), "NETWORK");
            }
            continue;
        }
       
        if (bytes_received == 0) {
            continue;
        }
       
        std::string client_ip = getClientIP(reinterpret_cast<struct sockaddr*>(&client_addr), addr_len);
        uint16_t client_port = ntohs(ipv6 ? 
            reinterpret_cast<struct sockaddr_in6*>(&client_addr)->sin6_port :
            reinterpret_cast<struct sockaddr_in*>(&client_addr)->sin_port);
       
        // Process query in thread pool
        std::vector<uint8_t> request_data(buffer.begin(), buffer.begin() + bytes_received);
       
        thread_pool->enqueue([this, request_data, client_ip, client_port, socket, client_addr, addr_len]() {
            processQuery(request_data, client_ip, client_port, socket, 
                        const_cast<struct sockaddr*>(reinterpret_cast<const struct sockaddr*>(&client_addr)), 
                        addr_len, false);
        });
    }
   
    LOG_INFO("UDP handler stopped for " + std::string(ipv6 ? "IPv6" : "IPv4"), "NETWORK");
}

void rslvd::processQuery(const std::vector<uint8_t>& request_data, 
                            const std::string& client_ip, uint16_t client_port,
                            SOCKET response_socket, struct sockaddr* client_addr, 
                            socklen_t addr_len, bool is_tcp) {
   
    auto start_time = std::chrono::steady_clock::now();
    total_queries++;
   
    try {
        // Check rate limiting
        if (rate_limiter && !rate_limiter->checkRateLimit(client_ip)) {
            LOG_WARNING("Rate limit exceeded for client: " + client_ip, "SECURITY");
            failed_queries++;
            return;
        }
       
        // Check ACL
        if (acl) {
            ACLAction action = acl->checkAccess(client_ip);
            if (action == ACLAction::DENY) {
                LOG_WARNING("Access denied for client: " + client_ip, "SECURITY");
                failed_queries++;
                return;
            }
        }
       
        // Parse DNS request
        DNSPacket request;
        if (!request.parse(request_data)) {
            LOG_WARNING("Failed to parse DNS request from " + client_ip, "DNS");
            failed_queries++;
            return;
        }
       
        // Create response
        std::vector<uint8_t> response_data = createResponse(request, client_ip);
       
        if (!response_data.empty()) {
            // Send response
            if (is_tcp) {
                // TCP response includes length prefix
                uint16_t length = htons(static_cast<uint16_t>(response_data.size()));
                std::vector<uint8_t> tcp_response;
                tcp_response.resize(2 + response_data.size());
                memcpy(tcp_response.data(), &length, 2);
                memcpy(tcp_response.data() + 2, response_data.data(), response_data.size());
               
                send(response_socket, reinterpret_cast<const char*>(tcp_response.data()), 
                     tcp_response.size(), 0);
            } else {
                sendto(response_socket, reinterpret_cast<const char*>(response_data.data()), 
                       response_data.size(), 0, client_addr, addr_len);
            }
           
            total_responses++;
           
            // Log query
            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
           
            if (!request.questions.empty()) {
                Logger::getInstance().logQuery(client_ip, request.questions[0].name,
                                             request.questions[0].type, 0, 
                                             static_cast<uint32_t>(duration.count()));
            }
        } else {
            failed_queries++;
        }
       
    } catch (const std::exception& e) {
        LOG_ERROR("Error processing query from " + client_ip + ": " + e.what(), "DNS");
        failed_queries++;
    }
}

std::vector<uint8_t> rslvd::createResponse(const DNSPacket& request, const std::string& client_ip) {
    DNSPacket response;
    response.header = request.header;
    response.header.qr = 1; // Response
    response.header.aa = 0; // Not authoritative by default
    response.header.ra = 1; // Recursion available
    response.header.rcode = DNS_RCODE_NOERROR;
   
    // Copy questions
    response.questions = request.questions;
   
    // Process each question
    for (const auto& question : request.questions) {
        std::vector<DNSRecord> records = lookupRecords(question.name, question.type);
       
        if (!records.empty()) {
            response.answers.insert(response.answers.end(), records.begin(), records.end());
           
            // Check if we're authoritative for this domain
            if (isAuthoritative(question.name)) {
                response.header.aa = 1;
            }
        } else {
            // No records found
            if (isAuthoritative(question.name)) {
                response.header.aa = 1;
                response.header.rcode = DNS_RCODE_NXDOMAIN;
            } else {
                response.header.rcode = DNS_RCODE_SERVFAIL;
            }
        }
    }
   
    // Update header counts
    response.header.qdcount = static_cast<uint16_t>(response.questions.size());
    response.header.ancount = static_cast<uint16_t>(response.answers.size());
    response.header.nscount = static_cast<uint16_t>(response.authority.size());
    response.header.arcount = static_cast<uint16_t>(response.additional.size());
   
    return response.serialize();
}

std::vector<DNSRecord> rslvd::lookupRecords(const std::string& name, uint16_t type) {
    // First check cache
    if (dns_cache) {
        std::vector<DNSRecord> cached_records = dns_cache->get(name, type);
        if (!cached_records.empty()) {
            cache_hits++;
            return cached_records;
        }
        cache_misses++;
    }
   
    // Look up in zones
    std::vector<DNSRecord> records = lookupInZones(name, type);
   
    // Cache the results if found
    if (!records.empty() && dns_cache) {
        uint32_t min_ttl = records[0].ttl;
        for (const auto& record : records) {
            min_ttl = std::min(min_ttl, record.ttl);
        }
        dns_cache->put(name, type, records, min_ttl);
    }
   
    return records;
}

std::vector<DNSRecord> rslvd::lookupInZones(const std::string& name, uint16_t type) {
    std::shared_lock<std::shared_mutex> lock(zones_mutex);
   
    std::vector<DNSRecord> results;
   
    // Direct lookup
    auto it = zones.find(name);
    if (it != zones.end()) {
        for (const auto& record : it->second) {
            if (record.type == type || type == 255) { // 255 = ANY
                results.push_back(record);
            }
        }
    }
   
    // CNAME lookup
    if (results.empty() && type != DNS_TYPE_CNAME) {
        auto cname_it = zones.find(name);
        if (cname_it != zones.end()) {
            for (const auto& record : cname_it->second) {
                if (record.type == DNS_TYPE_CNAME) {
                    results.push_back(record);
                    // Follow CNAME chain
                    auto target_records = lookupInZones(record.data, type);
                    results.insert(results.end(), target_records.begin(), target_records.end());
                    break;
                }
            }
        }
    }
   
    return results;
}

void rslvd::loadZones() {
    auto config = config_manager->getConfig();
   
    try {
        if (!std::filesystem::exists(config.zones_directory)) {
            LOG_WARNING("Zones directory does not exist: " + config.zones_directory, "ZONES");
            return;
        }
       
        std::unique_lock<std::shared_mutex> lock(zones_mutex);
        zones.clear();
       
        for (const auto& entry : std::filesystem::directory_iterator(config.zones_directory)) {
            if (entry.is_regular_file() && entry.path().extension() == ".zone") {
                loadZoneFile(entry.path().string());
            }
        }
       
        LOG_INFO("Loaded " + std::to_string(zones.size()) + " zone entries", "ZONES");
       
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to load zones: " + std::string(e.what()), "ZONES");
    }
}

bool rslvd::loadZoneFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open zone file: " + filename, "ZONES");
        return false;
    }
   
    std::string line;
    std::string current_origin;
    uint32_t default_ttl = 3600;
   
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == ';') {
            continue;
        }
       
        // Parse zone record (simplified)
        std::istringstream iss(line);
        std::string name, ttl_or_class, class_or_type, type_or_data, data;
       
        if (!(iss >> name)) continue;
       
        // Handle $ORIGIN directive
        if (name == "$ORIGIN") {
            iss >> current_origin;
            continue;
        }
       
        // Handle $TTL directive
        if (name == "$TTL") {
            iss >> default_ttl;
            continue;
        }
       
        // Parse record
        iss >> ttl_or_class >> class_or_type >> type_or_data;
        std::getline(iss, data);
       
        // Simplified parsing - in production, use a proper zone file parser
        DNSRecord record;
        record.name = name;
        record.ttl = default_ttl;
        record.class_type = DNS_CLASS_IN;
       
        if (class_or_type == "A") {
            record.type = DNS_TYPE_A;
            record.data = type_or_data;
        } else if (class_or_type == "AAAA") {
            record.type = DNS_TYPE_AAAA;
            record.data = type_or_data;
        } else if (class_or_type == "CNAME") {
            record.type = DNS_TYPE_CNAME;
            record.data = type_or_data;
        } else if (class_or_type == "MX") {
            record.type = DNS_TYPE_MX;
            record.data = type_or_data + " " + data;
        } else if (class_or_type == "TXT") {
            record.type = DNS_TYPE_TXT;
            record.data = type_or_data + data;
        }
       
        zones[record.name].push_back(record);
    }
   
    LOG_INFO("Loaded zone file: " + filename, "ZONES");
    return true;
}

void rslvd::signalHandler(int signal) {
    if (instance) {
        switch (signal) {
            case SIGINT:
            case SIGTERM:
                LOG_INFO("Received shutdown signal", "SERVER");
                instance->shutdown_requested = true;
                instance->stop();
                break;
#ifndef _WIN32
            case SIGHUP:
                LOG_INFO("Received reload signal", "SERVER");
                instance->reloadConfiguration();
                break;
#endif
        }
    }
}

void rslvd::stop() {
    if (!running.load()) {
        return;
    }
   
    LOG_INFO("Stopping RSLVD DNS...", "SERVER");
    running = false;
   
    // Stop metrics server
    if (metrics) {
        metrics->stop();
    }
   
    // Close sockets to break out of blocking calls
    cleanupSockets();
   
    // Wait for network threads to finish
    for (auto& thread : network_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    network_threads.clear();
   
    LOG_INFO("RSLVD DNS stopped", "SERVER");
}

void rslvd::shutdown() {
    stop();
   
    // Stop zone reload thread
    if (zone_reload_thread.joinable()) {
        zone_reload_thread.join();
    }
   
    // Shutdown thread pool
    if (thread_pool) {
        thread_pool->shutdown();
    }
   
    LOG_INFO("RSLVD DNS shutdown complete", "SERVER");
}

void rslvd::cleanupSockets() {
    if (udp_socket_v4 != INVALID_SOCKET) {
        CLOSE_SOCKET(udp_socket_v4);
        udp_socket_v4 = INVALID_SOCKET;
    }
   
    if (udp_socket_v6 != INVALID_SOCKET) {
        CLOSE_SOCKET(udp_socket_v6);
        udp_socket_v6 = INVALID_SOCKET;
    }
   
    if (tcp_socket_v4 != INVALID_SOCKET) {
        CLOSE_SOCKET(tcp_socket_v4);
        tcp_socket_v4 = INVALID_SOCKET;
    }
   
    if (tcp_socket_v6 != INVALID_SOCKET) {
        CLOSE_SOCKET(tcp_socket_v6);
        tcp_socket_v6 = INVALID_SOCKET;
    }
}

void rslvd::handleTCPRequests(SOCKET socket, bool ipv6) {
    LOG_INFO("TCP handler started for " + std::string(ipv6 ? "IPv6" : "IPv4"), "NETWORK");
   
    while (running.load()) {
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);
       
        SOCKET client_socket = accept(socket, reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
       
        if (client_socket == INVALID_SOCKET) {
            if (running.load()) {
                LOG_ERROR("TCP accept error: " + std::to_string(GET_SOCKET_ERROR()), "NETWORK");
            }
            continue;
        }
       
        std::string client_ip = getClientIP(reinterpret_cast<struct sockaddr*>(&client_addr), addr_len);
       
        // Handle connection in thread pool
        thread_pool->enqueue([this, client_socket, client_ip]() {
            handleTCPConnection(client_socket, client_ip);
        });
    }
   
    LOG_INFO("TCP handler stopped for " + std::string(ipv6 ? "IPv6" : "IPv4"), "NETWORK");
}

void rslvd::handleTCPConnection(SOCKET client_socket, const std::string& client_ip) {
    auto config = config_manager->getConfig();
   
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = config.tcp_timeout_seconds;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, 
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, 
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
   
    try {
        while (running.load()) {
            // Read length prefix (2 bytes)
            uint16_t length;
            int bytes_received = recv(client_socket, reinterpret_cast<char*>(&length), 2, MSG_WAITALL);
           
            if (bytes_received != 2) {
                break; // Connection closed or error
            }
           
            length = ntohs(length);
            if (length == 0 || length > MAX_TCP_DNS_PACKET_SIZE) {
                LOG_WARNING("Invalid TCP DNS packet length from " + client_ip + ": " + std::to_string(length), "NETWORK");
                break;
            }
           
            // Read DNS packet
            std::vector<uint8_t> buffer(length);
            bytes_received = recv(client_socket, reinterpret_cast<char*>(buffer.data()), length, MSG_WAITALL);
           
            if (bytes_received != length) {
                break; // Connection closed or error
            }
           
            // Process query
            processQuery(buffer, client_ip, 0, client_socket, nullptr, 0, true);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("TCP connection error with " + client_ip + ": " + e.what(), "NETWORK");
    }
   
    CLOSE_SOCKET(client_socket);
}

std::string rslvd::getClientIP(struct sockaddr* addr, socklen_t addr_len) {
    char ip_str[INET6_ADDRSTRLEN];
   
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in* addr_in = reinterpret_cast<struct sockaddr_in*>(addr);
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6* addr_in6 = reinterpret_cast<struct sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
    } else {
        return "unknown";
    }
   
    return std::string(ip_str);
}

bool rslvd::isAuthoritative(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(zones_mutex);
   
    // Check if we have any records for this domain or its parent domains
    std::string domain = name;
    while (!domain.empty()) {
        if (zones.find(domain) != zones.end()) {
            return true;
        }
       
        size_t dot_pos = domain.find('.');
        if (dot_pos == std::string::npos) {
            break;
        }
        domain = domain.substr(dot_pos + 1);
    }
   
    return false;
}

void rslvd::watchZoneFiles() {
    auto config = config_manager->getConfig();
   
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(config.zone_reload_interval_seconds));
       
        if (!running.load()) break;
       
        try {
            // Check for zone file changes and reload if necessary
            reloadZones();
        } catch (const std::exception& e) {
            LOG_ERROR("Error during zone file watching: " + std::string(e.what()), "ZONES");
        }
    }
}

void rslvd::reloadZones() {
    LOG_INFO("Reloading zones...", "ZONES");
    loadZones();
}

bool rslvd::reloadConfiguration() {
    try {
        if (config_manager->reloadConfig()) {
            LOG_INFO("Configuration reloaded successfully", "CONFIG");
            return true;
        } else {
            LOG_ERROR("Failed to reload configuration", "CONFIG");
            return false;
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception during configuration reload: " + std::string(e.what()), "CONFIG");
        return false;
    }
}

ServerConfig rslvd::getConfiguration() const {
    return config_manager->getConfig();
}

bool rslvd::addZone(const std::string& zone_name, const std::vector<DNSRecord>& records) {
    std::unique_lock<std::shared_mutex> lock(zones_mutex);
    zones[zone_name] = records;
    LOG_INFO("Added zone: " + zone_name, "ZONES");
    return true;
}

bool rslvd::removeZone(const std::string& zone_name) {
    std::unique_lock<std::shared_mutex> lock(zones_mutex);
    auto it = zones.find(zone_name);
    if (it != zones.end()) {
        zones.erase(it);
        LOG_INFO("Removed zone: " + zone_name, "ZONES");
        return true;
    }
    return false;
}

std::vector<std::string> rslvd::getZones() const {
    std::shared_lock<std::shared_mutex> lock(zones_mutex);
    std::vector<std::string> zone_names;
   
    for (const auto& zone : zones) {
        zone_names.push_back(zone.first);
    }
   
    return zone_names;
}

rslvd::ServerStats rslvd::getStats() const {
    ServerStats stats;
    stats.total_queries = total_queries.load();
    stats.total_responses = total_responses.load();
    stats.failed_queries = failed_queries.load();
    stats.cache_hits = cache_hits.load();
    stats.cache_misses = cache_misses.load();
    stats.active_connections = rate_limiter ? rate_limiter->getActiveConnections() : 0;
   
    {
        std::shared_lock<std::shared_mutex> lock(zones_mutex);
        stats.zones_loaded = static_cast<uint32_t>(zones.size());
    }
   
    static auto start_time = std::chrono::steady_clock::now();
    stats.start_time = start_time;
    auto now = std::chrono::steady_clock::now();
    stats.uptime_seconds = std::chrono::duration<double>(now - start_time).count();
   
    return stats;
}

void rslvd::resetStats() {
    total_queries = 0;
    total_responses = 0;
    failed_queries = 0;
    cache_hits = 0;
    cache_misses = 0;
   
    if (rate_limiter) {
        rate_limiter->resetStats();
    }
   
    if (dns_cache) {
        dns_cache->resetStats();
    }
}

bool rslvd::isHealthy() const {
    return running.load() && !shutdown_requested.load();
}

std::string rslvd::getHealthStatus() const {
    if (!running.load()) {
        return "Server is not running";
    }
   
    if (shutdown_requested.load()) {
        return "Server shutdown requested";
    }
   
    auto stats = getStats();
   
    std::ostringstream oss;
    oss << "Server is healthy\n";
    oss << "Uptime: " << static_cast<int>(stats.uptime_seconds) << " seconds\n";
    oss << "Total queries: " << stats.total_queries << "\n";
    oss << "Active connections: " << stats.active_connections << "\n";
    oss << "Zones loaded: " << stats.zones_loaded;
   
    return oss.str();
}

uint16_t rslvd::generateTransactionId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint16_t> dis;
    return dis(gen);
}
