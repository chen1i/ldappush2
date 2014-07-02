#pragma once

#include <string>
#include <boost/shared_ptr.hpp>
#include <mordor/json.h>

namespace dpc {

typedef std::string AuthorizationHeader;
typedef std::string JobId;
typedef Mordor::JSON::Object SyncConfig;

const std::string SERVER_ROOT = "services.mozy.com";

class BifrostClient
{
public:
    BifrostClient(std::string partner_id, std::string svc_endpoint = SERVER_ROOT);
    ~BifrostClient(void);
    
    typedef boost::shared_ptr<BifrostClient> ptr;

    // Bifrost API about fedid sync
    AuthorizationHeader SvcAuthenticate();
    SyncConfig SvcGetSyncConfig();
    JobId SubmitSyncData();
    bool CheckApiKey(std::string key_txt);
    int ReportVersion(std::string version_txt);
    int CheckLatestClientVersion();

};

}; //dpc namespace
