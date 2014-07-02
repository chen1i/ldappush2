#pragma once
#include <string>
#include <boost/shared_ptr.hpp>

namespace dpc {

class LdapClient
{
public:
    LdapClient(std::string host, int port, std::string user, std::string password);
    ~LdapClient(void);

    typedef boost::shared_ptr<LdapClient> ptr;
    bool ConnectLdap(std::string base_dn="");
    int QueryLdap(std::string filter, size_t page); //need a callback to process paginating?
};

}; //dpc namespace
