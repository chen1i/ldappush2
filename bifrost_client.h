#pragma once

#include <string>
#include <boost/shared_ptr.hpp>
#include <mordor/json.h>
#include <mordor/uri.h>
#include <mordor/iomanager.h>
#include <mordor/http/client.h>

namespace dpc {

const std::string SERVER_ROOT = "https://services.mozy.com";
const std::string AUTH_PATH = "/auth/exchange";
const std::string SYNCCONFIG_PATH = "/fedid/sync_configs";
const std::string SYNCJOBS_PATH = "/fedid/syncjobs";
const std::string VERSION_PATH= "/fedid/connector_version/";
const std::string VERSION_ALERT_PATH = "/fedid/connector_version_events";
const std::string REGISTER_PATH = "/fedid/connector_register/";

class BifrostClient
{
public:
    typedef std::string AuthorizationHeader;
    typedef std::string JobId;
    typedef Mordor::JSON::Object SyncConfig;
    typedef boost::shared_ptr<BifrostClient> ptr;

    BifrostClient(std::string partner_id, std::string key_text, std::string svc_address = SERVER_ROOT);
    ~BifrostClient(void);

    // Bifrost API about fedid sync
    AuthorizationHeader SvcAuthenticate(bool force_new = false);
    SyncConfig SvcGetSyncConfig();
    JobId SubmitSyncData();
    bool CheckApiKey();
    int ReportVersion(std::string version_txt);
    int CheckLatestClientVersion();

private:
    std::string authenticate();
    Mordor::HTTP::ClientRequest::ptr makeClientRequestObj(Mordor::HTTP::Request& rh, std::string path);

private:
    std::string partner_id_;
    std::string api_key_;

    Mordor::URI root_uri_;
    boost::shared_ptr<Mordor::IOManager> io_mgr_;
    std::string auth_token_;

};

}; //dpc namespace
