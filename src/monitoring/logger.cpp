#include "monitoring/logger.h"
#include <filesystem>
#include <iomanip>

std::unique_ptr<Logger> Logger::instance = nullptr;
std::mutex Logger::instance_mutex;

Logger::Logger() 
    : min_level(LogLevel::INFO), console_output(true), file_output(true),
      max_file_size(100 * 1024 * 1024), max_files(10) {
}

Logger::~Logger() {
    if (log_file.is_open()) {
        log_file.close();
    }
}

Logger& Logger::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::make_unique<Logger>();
    }
    return *instance;
}

void Logger::configure(const std::string& log_dir, LogLevel level, 
                      bool console, bool file, size_t max_size, size_t max_count) {
    std::lock_guard<std::mutex> lock(log_mutex);
   
    log_directory = log_dir;
    min_level = level;
    console_output = console;
    file_output = file;
    max_file_size = max_size;
    max_files = max_count;
   
    if (file_output) {
        try {
            std::filesystem::create_directories(log_directory);
            std::string log_path = log_directory + "/rslvd.log";
            log_file.open(log_path, std::ios::app);
           
            if (!log_file.is_open()) {
                std::cerr << "Failed to open log file: " << log_path << std::endl;
                file_output = false;
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to create log directory: " << e.what() << std::endl;
            file_output = false;
        }
    }
}

void Logger::log(LogLevel level, const std::string& message, const std::string& component) {
    if (level < min_level) {
        return;
    }
   
    std::lock_guard<std::mutex> lock(log_mutex);
   
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
   
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    oss << " [" << levelToString(level) << "]";
   
    if (!component.empty()) {
        oss << " [" << component << "]";
    }
   
    oss << " " << message;
   
    std::string log_line = oss.str();
   
    if (console_output) {
        if (level >= LogLevel::ERROR) {
            std::cerr << log_line << std::endl;
        } else {
            std::cout << log_line << std::endl;
        }
    }
   
    if (file_output && log_file.is_open()) {
        log_file << log_line << std::endl;
        log_file.flush();
       
        // Check if rotation is needed
        if (log_file.tellp() > static_cast<std::streampos>(max_file_size)) {
            rotateLogFile();
        }
    }
}

void Logger::rotateLogFile() {
    if (!log_file.is_open()) {
        return;
    }
   
    log_file.close();
   
    try {
        // Rotate existing log files
        for (int i = max_files - 1; i > 0; --i) {
            std::string old_name = log_directory + "/rslvd.log." + std::to_string(i);
            std::string new_name = log_directory + "/rslvd.log." + std::to_string(i + 1);
           
            if (std::filesystem::exists(old_name)) {
                if (i == static_cast<int>(max_files - 1)) {
                    std::filesystem::remove(old_name);
                } else {
                    std::filesystem::rename(old_name, new_name);
                }
            }
        }
       
        // Move current log to .1
        std::string current_log = log_directory + "/rslvd.log";
        std::string rotated_log = log_directory + "/rslvd.log.1";
       
        if (std::filesystem::exists(current_log)) {
            std::filesystem::rename(current_log, rotated_log);
        }
       
        // Open new log file
        log_file.open(current_log, std::ios::app);
       
    } catch (const std::exception& e) {
        std::cerr << "Failed to rotate log file: " << e.what() << std::endl;
    }
}

std::string Logger::levelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRIT";
        default: return "UNKNOWN";
    }
}

void Logger::debug(const std::string& message, const std::string& component) {
    log(LogLevel::DEBUG, message, component);
}

void Logger::info(const std::string& message, const std::string& component) {
    log(LogLevel::INFO, message, component);
}

void Logger::warning(const std::string& message, const std::string& component) {
    log(LogLevel::WARNING, message, component);
}

void Logger::error(const std::string& message, const std::string& component) {
    log(LogLevel::ERROR, message, component);
}

void Logger::critical(const std::string& message, const std::string& component) {
    log(LogLevel::CRITICAL, message, component);
}

void Logger::logQuery(const std::string& client_ip, const std::string& query_name,
                     uint16_t query_type, uint16_t response_code, uint32_t response_time_ms) {
    std::ostringstream oss;
    oss << "QUERY client=" << client_ip
        << " name=" << query_name
        << " type=" << query_type 
        << " rcode=" << response_code
        << " time=" << response_time_ms << "ms";
   
    log(LogLevel::INFO, oss.str(), "DNS");
}

void Logger::logDDNSUpdate(const std::string& client_ip, const std::string& zone,
                          const std::string& record_name, const std::string& operation) {
    std::ostringstream oss;
    oss << "DDNS_UPDATE client=" << client_ip
        << " zone=" << zone
        << " record=" << record_name
        << " op=" << operation;
   
    log(LogLevel::INFO, oss.str(), "DDNS");
}

void Logger::logSecurityEvent(const std::string& event_type, const std::string& client_ip,
                             const std::string& details) {
    std::ostringstream oss;
    oss << "SECURITY_EVENT type=" << event_type 
        << " client=" << client_ip
        << " details=" << details;
   
    log(LogLevel::WARNING, oss.str(), "SECURITY");
}