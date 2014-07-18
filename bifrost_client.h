#pragma once

#include <string>
#include <boost/shared_ptr.hpp>
#include <mordor/json.h>
#include <mordor/uri.h>
#include <mordor/iomanager.h>
#include <mordor/streams/ssl.h>
#include <mordor/http/client.h>
#include <mordor/http/broker.h>

namespace dpc {

const std::string SERVER_ROOT = "https://services.mozy.com";
const std::string AUTH_PATH = "/auth/exchange";
const std::string SYNCCONFIG_PATH = "/fedid/sync_configs";
const std::string SYNCJOBS_PATH = "/fedid/syncjobs";
const std::string VERSION_PATH= "/fedid/connector_version/";
const std::string VERSION_ALERT_PATH = "/fedid/connector_version_events";
const std::string REGISTER_PATH = "/fedid/connector_register/";

class Settings;

class BifrostClient
{
public:
    typedef std::string AuthorizationHeader;
    typedef std::string JobId;
    typedef Mordor::JSON::Object SyncConfig;
    typedef boost::shared_ptr<BifrostClient> ptr;

    explicit BifrostClient(Settings& all_option);
    ~BifrostClient(void);

    // Bifrost APIs for fedid sync
    AuthorizationHeader SvcAuthenticate(bool force_new = false);
    SyncConfig SvcGetSyncConfig();
    JobId SubmitSyncData();
    bool CheckApiKey();
    int ReportVersion(std::string version_txt);
    int CheckLatestClientVersion();

private:
    std::string authenticate();
    Mordor::HTTP::RequestBroker::ptr makeClientRequestObj(Mordor::HTTP::Request& rh, std::string path);
    void initSSLCertificates();

private:
    // config attributes copied from Settings obj
    std::string partner_id_;
    std::string api_key_;
    bool check_ssl_;
    std::string proxy_uri_;
    std::string proxy_user_;
    std::string proxy_password_;

    // runtime attributes
    boost::shared_ptr<SSL_CTX> ssl_ctx_;
    Mordor::URI root_uri_;
    boost::shared_ptr<Mordor::IOManager> io_mgr_;
    std::string auth_token_;

};

}; //dpc namespace
