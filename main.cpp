// CodeJam.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <mordor/config.h>
#include <mordor/main.h>
using namespace Mordor;

#include "sync_worker.h"
#include "logger.h"
using namespace dpc;

const int DPC_CONFIG_FAILED = -1;
const int DPC_SYNC_FAILED   = -2;
const int DPC_SUCCESS       = 0;

int do_config(Settings& setting);
int do_sync(dpc::Settings& setting);

//static ConfigVar<std::string>::ptr log_file_setting = Config::lookup<std::string>("log.file1", std::string("ldap_connector.log"), "log file");
REGISTER_LOGGER("dpc:connector:main");

MORDOR_MAIN(int argc, char* argv[])
{
    Config::loadFromEnvironment();
#ifdef WINDOWS
    g_log->addSink(Mordor::LogSink::ptr(new dpc::EventLogSink(ComponentName, SourceName)));
#endif
    Config::lookup("log.file")->fromString("z.log");
    Config::lookup("log.stdout")->fromString("1");
//    Config::lookup("log.debug")->fromString("1"); //# also add environment var LOG_DEBUGMASK=xxx in VS Debug setting
    MORDOR_LOG_DEBUG(g_log)<<"can you see this debug?";
    MORDOR_LOG_INFO(g_log)<<"can you see this info?";
    MORDOR_LOG_WARNING(g_log)<<"can you see this warning?";
    MORDOR_LOG_ERROR(g_log)<<"can you see this error?";
    MORDOR_LOG_FATAL(g_log)<<"can you see this fatal?";

    Settings mysetting;
    mysetting.ParseCLI(argc, argv);

    if (mysetting.IsConfigMode())
        do_config(mysetting);
    else
        do_sync(mysetting);
    
    MORDOR_LOG_ERROR(g_log)<<"can you see this?";
	return 0;
}

int do_config(Settings& setting)
{
    BifrostClient bifrost(setting.PartnerId(), setting.BifrostEndpoint());

    if (bifrost.CheckApiKey(setting.ApiKey()) == false)
        return DPC_CONFIG_FAILED;

    // bifrost instance is valid from now on.
    // it can be used to do version report/check
    bifrost.ReportVersion(setting.CurrentVersion());

    bifrost.CheckLatestClientVersion();

    return setting.PersistToRegistry();
}

int do_sync(dpc::Settings& setting)
{
    BifrostClient::ptr bifrost(new BifrostClient(setting.PartnerId(), setting.BifrostEndpoint()));
    bifrost->ReportVersion(setting.CurrentVersion());
    bifrost->CheckLatestClientVersion();

    //bifrost is pointing to a usable instance to talk with endpoint
    
    LdapClient::ptr ldap(new LdapClient(setting.LdapHost(), setting.LdapPort(), setting.LdapUser(), setting.LdapPassword()));
    ldap->ConnectLdap(setting.LdapBaseDN());

    // ldap is pointing to a usable instance from now on

    SyncWorker worker(bifrost, ldap, setting);
    worker.run();

    return 0;
}

