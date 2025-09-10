README.md (Updated)

# Production DNS Server

A high-performance, secure, and feature-rich DNS server implementation in C++ designed for production environments.

## Features

### Core DNS Functionality
- Full DNS protocol support (RFC 1035, 1123, 2181)
- UDP and TCP transport protocols
- IPv4 and IPv6 dual-stack support
- Authoritative DNS server capabilities
- Dynamic DNS (DDNS) updates with TSIG authentication
- Comprehensive zone file management

### Security Features
- Rate limiting with configurable thresholds
- Access Control Lists (ACL) with network-based rules
- HMAC-based authentication for updates
- Input validation and sanitization
- Security event logging and monitoring
- Protection against DNS amplification attacks

### Performance Features
- Multi-threaded architecture with thread pool
- High-performance DNS cache with LRU eviction
- Connection pooling and management
- Optimized packet processing
- Memory-efficient data structures
- Configurable performance tuning

### Monitoring & Observability
- Structured JSON logging with rotation
- Prometheus metrics integration
- Real-time performance statistics
- Health check endpoints
- Grafana dashboard support
- Comprehensive error tracking

### Reliability Features
- Graceful shutdown and restart
- Configuration hot-reloading
- Automatic zone file reloading
- Robust error handling and recovery
- Service management integration
- High availability support

## Quick Start

### Prerequisites
- C++17 compatible compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.16+
- OpenSSL 1.1.1+
- Docker (optional)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/production-rslvd.git
cd production-rslvd

# Create build directory
mkdir build && cd build

# Configure and build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install (optional)
sudo make install
Docker Deployment

# Build and start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f rslvd

# Stop services
docker-compose down
Configuration

The server uses a comprehensive configuration file located at config/rslvd.conf:

# Server settings
port=53
bind_address="0.0.0.0"
enable_tcp=true
enable_udp=true
enable_ipv6=true

# Performance settings
thread_pool_size=8
max_concurrent_connections=1000

# Security settings
enable_rate_limiting=true
max_queries_per_second=100
enable_acl=true

# Cache settings
enable_cache=true
cache_max_entries=10000
cache_max_memory_mb=100
Zone Configuration

Create zone files in the config/zones/ directory:

; example.com.zone
$ORIGIN example.com.
$TTL 3600

@       IN  SOA ns1.example.com. admin.example.com. (
                2024010101  ; Serial
                3600        ; Refresh
                1800        ; Retry
                604800      ; Expire
                86400       ; Minimum TTL
                )

@       IN  NS  ns1.example.com.
@       IN  NS  ns2.example.com.
@       IN  A   192.0.2.1
www     IN  A   192.0.2.2
mail    IN  A   192.0.2.3
@       IN  MX  10 mail.example.com.
Usage
Starting the Server

# Start with default configuration
./rslvd

# Start with custom configuration
./rslvd -c /path/to/config.conf

# Run as daemon
./rslvd -d

# Test configuration
./rslvd --test-config
Command Line Options

Usage: rslvd [options]
Options:
  -c, --config <file>    Configuration file path
  -d, --daemon          Run as daemon
  -h, --help            Show help message
  -v, --version         Show version information
  --test-config         Test configuration and exit
Testing DNS Resolution

# Test A record lookup
dig @localhost example.com A

# Test with specific port
dig @localhost -p 5353 example.com A

# Test IPv6
dig @::1 example.com AAAA

# Test TCP
dig @localhost +tcp example.com A
Monitoring
Prometheus Metrics

The server exposes metrics on port 8080 (configurable):

curl http://localhost:8080/metrics

Key metrics include:

    dns_queries_total - Total DNS queries received
    dns_responses_total - Total DNS responses sent
    dns_cache_hits_total - Cache hit count
    dns_errors_total - Error count by type
    dns_response_time_seconds - Response time histogram

Health Checks

# Check server health
curl http://localhost:8080/health

# Get detailed status
curl http://localhost:8080/status
Log Analysis

Logs are written in structured JSON format:

{
  "timestamp": "2024-01-01T12:00:00Z",
  "level": "INFO",
  "component": "DNS",
  "message": "Query processed",
  "client_ip": "192.0.2.100",
  "query_name": "example.com",
  "query_type": "A",
  "response_code": 0,
  "response_time_ms": 5
}
Security
Access Control

Configure network-based access control in config/acl.conf:

# Allow private networks
192.168.0.0/16 allow Private network
10.0.0.0/8 allow Private network

# Require authentication for updates
0.0.0.0/0 require_auth External networks
DDNS Authentication

Generate TSIG keys for secure dynamic updates:

# Generate key
openssl rand -base64 32 > ddns.key

# Configure in keys file
echo "update-key:hmac-sha256:$(cat ddns.key)" >> config/keys/ddns.keys
Rate Limiting

Configure rate limits to prevent abuse:

enable_rate_limiting=true
max_queries_per_second=100
max_queries_per_minute=1000


# Performance Tuning
## System Configuration
### Increase file descriptor limits
'''
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf
'''

### Optimize network buffers
'''
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
'''

#Application Tuning
### Increase thread pool size for high load
'''
thread_pool_size=16
'''
### Optimize cache settings
'''
cache_max_entries=50000
cache_max_memory_mb=500
'''
### Adjust connection limits
'''
max_concurrent_connections=5000
'''

# Troubleshooting
# Common Issues
##Permission denied on port 53
###Run with elevated privileges or use alternative port
'''
sudo ./rslvd
'''
### or
'''
./rslvd -c config_alt_port.conf
'''
## High memory usage
### Reduce cache size in configuration
'''
cache_max_memory_mb=50
'''
## Connection timeouts
### Check firewall settings
'''
sudo ufw allow 53/udp
sudo ufw allow 53/tcp
'''
# Debug Mode
## Enable debug logging for troubleshooting:
'''
log_level="DEBUG"
Performance Analysis
'''
## Use built-in statistics:
### Get real-time statistics
'''
curl http://localhost:8080/stats
'''
## Monitor query patterns
'''
tail -f logs/rslvd.log | jq '.query_name' | sort | uniq -c
'''
### Check cache performance
'''
curl http://localhost:8080/metrics | grep cache
'''

# Development
## Building with Tests
'''
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
make test
'''
## Code Coverage
'''
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON
make coverage
'''

# Static Analysis
### Using clang-tidy
'''
clang-tidy src/*.cpp -- -Isrc
'''
### Using cppcheck
'''
cppcheck --enable=all src/
'''
# Contributing
    Fork the repository
    Create a feature branch: git checkout -b feature-name