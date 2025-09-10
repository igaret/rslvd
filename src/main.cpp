#include "rslvd.h"
#include "monitoring/logger.h"
#include <iostream>
#include <csignal>

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config <file>    Configuration file path (default: config/rslvd.conf)\n";
    std::cout << "  -d, --daemon          Run as daemon\n";
    std::cout << "  -h, --help            Show this help message\n";
    std::cout << "  -v, --version         Show version information\n";
    std::cout << "  --test-config         Test configuration and exit\n";
}

void printVersion() {
    std::cout << "Production RSLVD DNS v1.0.0\n";
    std::cout << "Built with security, performance, and reliability features\n";
}

int main(int argc, char* argv[]) {
    std::string config_file = "config/rslvd.conf";
    bool daemon_mode = false;
    bool test_config = false;
   
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
       
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            printVersion();
            return 0;
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            } else {
                std::cerr << "Error: --config requires a file path\n";
                return 1;
            }
        } else if (arg == "-d" || arg == "--daemon") {
            daemon_mode = true;
        } else if (arg == "--test-config") {
            test_config = true;
        } else {
            std::cerr << "Error: Unknown option " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }
   
    try {
        // Initialize RSLVD DNS
        rslvd server;
       
        if (!server.initialize(config_file)) {
            std::cerr << "Failed to initialize RSLVD DNS\n";
            return 1;
        }
       
        if (test_config) {
            std::cout << "Configuration test successful\n";
            return 0;
        }
       
        // Daemonize if requested
        if (daemon_mode) {
#ifndef _WIN32
            pid_t pid = fork();
            if (pid < 0) {
                std::cerr << "Failed to fork daemon process\n";
                return 1;
            }
            if (pid > 0) {
                // Parent process exits
                return 0;
            }
           
            // Child process continues as daemon
            setsid();
            chdir("/");
           
            // Close standard file descriptors
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
#else
            std::cerr << "Daemon mode not supported on Windows\n";
            return 1;
#endif
        }
       
        // Start the server
        if (!server.start()) {
            LOG_ERROR("Failed to start RSLVD DNS", "MAIN");
            return 1;
        }
       
        LOG_INFO("RSLVD DNS started successfully", "MAIN");
       
        if (!daemon_mode) {
            std::cout << "RSLVD DNS is running. Press Ctrl+C to stop.\n";
            std::cout << "Server statistics:\n";
           
            // Print periodic statistics
            while (server.isHealthy()) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
               
                auto stats = server.getStats();
                std::cout << "\r";
                std::cout << "Queries: " << stats.total_queries
                         << " | Responses: " << stats.total_responses
                         << " | Failed: " << stats.failed_queries
                         << " | Cache Hits: " << stats.cache_hits
                         << " | Active Connections: " << stats.active_connections
                         << " | Uptime: " << static_cast<int>(stats.uptime_seconds) << "s";
                std::cout.flush();
            }
        } else {
            // In daemon mode, just wait for shutdown
            while (server.isHealthy()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
       
        LOG_INFO("RSLVD DNS shutting down", "MAIN");
        server.shutdown();
       
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        LOG_ERROR("Fatal error: " + std::string(e.what()), "MAIN");
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        LOG_ERROR("Unknown fatal error occurred", "MAIN");
        return 1;
    }
   
    return 0;
}
