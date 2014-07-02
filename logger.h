#pragma once

#include <string>
#include <mordor/log.h>

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
}; //dpc namespace
