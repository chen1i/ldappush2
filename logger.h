#pragma once

#include <string>
#include <mordor/log.h>
#include <mordor/thread.h>

namespace dpc {

#define REGISTER_LOGGER(label) \
    static Mordor::Logger::ptr g_log = Mordor::Log::lookup((label));

class Logger
{
public:
    Logger(void);
    ~Logger(void);

    void LogError(std::string& msg);
    //void LogWarning(std::string& msg);
    //void LogInfo(std::string& msg);
    //void LogVerbose(std::string& msg);

private:
    int writeLog(std::string& msg, Mordor::Log::Level log_level = Mordor::Log::INFO);
private:
    Mordor::Logger::ptr log_;
};

#ifdef WINDOWS
/*
 * Windows specific only, use EventLog service to log message.
 */
const std::string ComponentName = "LDAPConnector";
const std::string SourceName = "LDAPConnectorEvt";

class EventLogSink : public Mordor::LogSink
{
public:
    /// @param subkey The subkey under HKLM/System/CurrentControlSet/Services/eventlog/
    /// @param source_name The event source column show in evnent viewer.
    EventLogSink(const std::string subkey, const std::string source_name);
    ~EventLogSink();

    void log(const std::string &logger,
        boost::posix_time::ptime now, unsigned long long elapsed,
        Mordor::tid_t thread, void *fiber,
        Mordor::Log::Level level, const std::string &str,
        const char *file, int line);
private:
    bool initializeRegistry(const std::string subkey, const std::string source_name);

private:
    std::string app_key_;
    std::string event_source_;
    HANDLE log_handler_;
};
#endif
}; //dpc namespace
