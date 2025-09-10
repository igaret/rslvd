#pragma once
#include "utils/utils.h"

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

class Logger {
private:
    static std::unique_ptr<Logger> instance;
    static std::mutex instance_mutex;
   
    std::ofstream log_file;
    std::mutex log_mutex;
    LogLevel min_level;
    bool console_output;
    bool file_output;
    std::string log_directory;
    size_t max_file_size;
    size_t max_files;
   
    void rotateLogFile();
    std::string levelToString(LogLevel level) const;
   
public:
    Logger();
    ~Logger();
   
    static Logger& getInstance();
   
    void configure(const std::string& log_dir, LogLevel level, 
                  bool console = true, bool file = true,
                  size_t max_size = 100 * 1024 * 1024, // 100MB
                  size_t max_count = 10);
   
    void log(LogLevel level, const std::string& message, 
             const std::string& component = "");
   
    void debug(const std::string& message, const std::string& component = "");
    void info(const std::string& message, const std::string& component = "");
    void warning(const std::string& message, const std::string& component = "");
    void error(const std::string& message, const std::string& component = "");
    void critical(const std::string& message, const std::string& component = "");
   
    // Structured logging for DNS queries
    void logQuery(const std::string& client_ip, const std::string& query_name,
                  uint16_t query_type, uint16_t response_code, 
                  uint32_t response_time_ms);
   
    void logDDNSUpdate(const std::string& client_ip, const std::string& zone,
                       const std::string& record_name, const std::string& operation);
   
    void logSecurityEvent(const std::string& event_type, const std::string& client_ip,
                         const std::string& details);
};

#define LOG_DEBUG(msg, comp) Logger::getInstance().debug(msg, comp)
#define LOG_INFO(msg, comp) Logger::getInstance().info(msg, comp)
#define LOG_WARNING(msg, comp) Logger::getInstance().warning(msg, comp)
#define LOG_ERROR(msg, comp) Logger::getInstance().error(msg, comp)
#define LOG_CRITICAL(msg, comp) Logger::getInstance().critical(msg, comp)
