#include "StdAfx.h"
#include "logger.h"

#include <boost/bind.hpp>
#include <iostream>

namespace dpc {

static Mordor::Logger::ptr  g_app_log = Mordor::Log::lookup("dpc:connector");

static void printLogger(std::ostream *os, Mordor::Logger::ptr lg)
{
    *os << lg->name() << " : " <<lg->level() << std::endl;
}
Logger::Logger(void)
{
    g_app_log->addSink(Mordor::LogSink::ptr(new Mordor::StdoutLogSink()));
    g_app_log->addSink(Mordor::LogSink::ptr(new Mordor::FileLogSink("codejam001.log")));
}

Logger::~Logger(void)
{
}

int Logger::writeLog(std::string& msg, Mordor::Log::Level log_level)
{
    //show all g_logs
    Mordor::Log::visit(boost::bind(&printLogger, &(std::cout), _1));

    MORDOR_LOG_ERROR(g_app_log)<<msg;
    MORDOR_LOG_INFO(g_app_log)<<msg;

    MORDOR_LOG_DEBUG(g_app_log)<<msg; //can not see it by default. should provide some config?
    return 0;
}

void Logger::LogError(std::string& msg)
{
    writeLog(msg, Mordor::Log::ERROR);
}

}