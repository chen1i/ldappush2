#pragma once
#include <string>
#include <boost/shared_ptr.hpp>

#include "sync_config.h"

namespace dpc {
class Settings;

class LdapClient
{
public:
    typedef boost::shared_ptr<LdapClient> ptr;

    LdapClient(const LdapConnectSetting& ldap_setting, const Settings local_setttings);
    ~LdapClient(void);

    void DumpConfig(const Settings local_settings);
    int QueryLdap(std::string filter, size_t page); //need a callback to process paginating?
    bool ConnectLdap();

private:
    //SyncConfig::ptr sync_config_;
    LdapConnectSetting ldap_server_;

    boost::shared_ptr<LDAP> ldap_session_;

    // runtime parameters for ldap query
    int query_timeout_;
    int page_size_;
};

}; //dpc namespace
