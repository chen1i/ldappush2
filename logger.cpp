#include "StdAfx.h"
#include "logger.h"
#include "win_helpers.h"
#include "SysEvent/LDAPConnectorEvent.h"

#include <boost/bind.hpp>
#include <iostream>
#include <mordor/string.h>

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

#ifdef WINDOWS
const std::string EventLogRootKey = "SYSTEM\\CurrentControlSet\\Services\\eventlog\\";
const Mordor::utf16string EventLogValueRetention = L"Retention";
const Mordor::utf16string EventLogValueSources = L"Sources";
const Mordor::utf16string EventLogSourceValueEventMessageFile = L"EventMessageFile";
const Mordor::utf16string EventLogSourceValueTypeSupported = L"TypesSupported";

EventLogSink::EventLogSink(const std::string subkey, const std::string source_name)
    :app_key_(subkey),
    event_source_(source_name)
{
    initializeRegistry(app_key_, event_source_); // make sure the Registry is there
}

EventLogSink::~EventLogSink()
{
    DeregisterEventSource(log_handler_);
}

void EventLogSink::log(const std::string &logger,
    boost::posix_time::ptime now,
    unsigned long long, // elapsed
    Mordor::tid_t, // thread
    void *, // fiber
    Mordor::Log::Level level,
    const std::string &str,
    const char *, // file
    int) // line
{
    //elapsed, thread, fiber, file and line are not writing to event log.
    WORD type;
    DWORD eventId;
    switch(level) {
        case Mordor::Log::FATAL:
        case Mordor::Log::ERROR:
            type = EVENTLOG_ERROR_TYPE;
            eventId = MSG_EVENTLOG_ERROR;
            break;
        case Mordor::Log::WARNING:
            type = EVENTLOG_WARNING_TYPE;
            eventId = MSG_EVENTLOG_WARN;
            break;
        case Mordor::Log::INFO:
            type = EVENTLOG_INFORMATION_TYPE;
            eventId = MSG_EVENTLOG_INFO;
            break;
        case Mordor::Log::DEBUG:
        case Mordor::Log::VERBOSE:
        case Mordor::Log::TRACE:
        case Mordor::Log::NONE:
            // won't dump to event log as this is too annoying
            return;
    }

    // normalize message to Unicode for windows system
    std::wstring message(str.begin(), str.end());
    const wchar_t * pMsg = message.c_str();

    ReportEvent(log_handler_, type, 0, eventId, 0, 1, 0, &pMsg, 0);
}

bool EventLogSink::initializeRegistry(const std::string subkey, const std::string source_name)
{
    // use RegSetValueEx to set value everytime
    // and haven't found a good way to handle Registry operation error in this place.
    // so just assume it barely happens
    Mordor::utf16string keyPath = Mordor::toUtf16(EventLogRootKey + subkey);
    Mordor::utf16string eventPath = keyPath.append(Mordor::toUtf16("\\\\" + source_name));

    HKEY keyHandle = NULL;
    HKEY eventHandle = NULL;

    LONG errorReturn = RegCreateKeyEx(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, NULL, 0, KEY_SET_VALUE | KEY_WRITE, NULL, &keyHandle, NULL);
    assert(keyHandle != NULL && errorReturn == ERROR_SUCCESS);

    errorReturn = RegSetValueEx(keyHandle, EventLogValueSources.c_str(), 0, REG_MULTI_SZ, (PBYTE)EventLogValueSources.c_str(), (EventLogValueSources.size() + 1) * sizeof(WCHAR));

    DWORD retention = 0;
    errorReturn =  RegSetValueEx(keyHandle, EventLogValueRetention.c_str(), 0, REG_DWORD, (LPBYTE)&retention, sizeof retention);

    errorReturn = RegCreateKeyEx(HKEY_LOCAL_MACHINE, eventPath.c_str(), 0, NULL, 0, KEY_SET_VALUE | KEY_WRITE, NULL, &eventHandle, NULL);
    assert(eventHandle != NULL && errorReturn == ERROR_SUCCESS);

    std::wstring msgDllPath = GetEventLogDllPath();
    errorReturn = RegSetValueEx(eventHandle, EventLogSourceValueEventMessageFile.c_str(), 0, REG_SZ, (PBYTE)msgDllPath.c_str(), (msgDllPath.size() + 1) * sizeof(WCHAR));

    DWORD eventTypes = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    errorReturn =  RegSetValueEx(eventHandle, EventLogSourceValueTypeSupported.c_str(), 0, REG_DWORD, (LPBYTE)&eventTypes, sizeof eventTypes);

    RegCloseKey(keyHandle);
    RegCloseKey(eventHandle);

    // obtain the handler of event log
    log_handler_ = RegisterEventSource(NULL, Mordor::toUtf16(source_name).c_str());
    return true;
}
#endif
}