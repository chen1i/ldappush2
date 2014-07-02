#pragma once
#include "ldap_client.h"
#include "bifrost_client.h"
#include "settings.h"

namespace dpc
{
class SyncWorker
{
public:
    SyncWorker(BifrostClient::ptr bifrost, LdapClient::ptr ldap, Settings& setting); // for normal run
    SyncWorker(std::string partner_id, std::string api_key, std::string svc_root = dpc::SERVER_ROOT); // for configuration
    ~SyncWorker(void);

    void run();
    

private:
    BifrostClient::ptr svc_;
    LdapClient::ptr ldap_;
    Settings config_;

};
}

