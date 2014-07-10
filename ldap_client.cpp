#include "StdAfx.h"
#include "ldap_client.h"
#include "logger.h"

REGISTER_LOGGER("dpc:connector:ldap");

namespace dpc {
LdapClient::LdapClient(std::string host, int port, std::string user, std::string password)
{
}

LdapClient::~LdapClient(void)
{
}

bool LdapClient::ConnectLdap(std::string base_dn)
{
    return false;
}

int LdapClient::QueryLdap(std::string filter, size_t page)
{
    return 0;
}

}