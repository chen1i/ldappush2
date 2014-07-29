#include "stdafx.h"
#include "ldap_client.h"

#include <iostream>
#include <mordor/string.h>
#include "logger.h"
#include "settings.h"
#include "win_helpers.h"

REGISTER_LOGGER("dpc:connector:ldap");

namespace dpc {
LdapClient::LdapClient(const LdapConnectSetting& ldap_setting, const Settings local_settings)
    :ldap_server_(ldap_setting),
    query_timeout_(local_settings.LdapQueryTimeout()),
    page_size_(local_settings.LdapPageSize())
{
    LDAP* p_ldap = NULL;
    if (ldap_server_.protocol == LDAPS) {
        p_ldap= ldap_sslinit(stdstring2LPWSTR(ldap_server_.host), ldap_server_.port, 1);
    } else {
        p_ldap= ldap_init(stdstring2LPWSTR(ldap_server_.host), ldap_server_.port);
    }
    if (p_ldap == NULL) {
        MORDOR_LOG_ERROR(g_log) << "ldap_init() or ldap_sslinit() triggered error " << LdapGetLastError()
            << " See MSDN documentation on LdapGetLastError() for details";
        assert(false);
    }
    // use deleter to make sure ldap session get cleaned up.
    ldap_session_.reset(p_ldap, boost::bind(&ldap_unbind, _1));
}

LdapClient::~LdapClient(void)
{
}

void LdapClient::DumpConfig(const Settings local_settings)
{
    std::cout<<" ------------------  show LdapConnectSetting here ----------------"<<std::endl;
}

static BOOLEAN ldap_server_cert_callback(PLDAP connection, PCCERT_CONTEXT pServerCert)
{
 if (CheckCertificateInStore(pServerCert, L"CA")
     ||CheckCertificateInStore(pServerCert, L"ROOT"))
     return TRUE;
 else
     return FALSE;
}
bool LdapClient::ConnectLdap()
{
    // make a full usable ldap session
    // set options
    ULONG lRtn = 0;
    int protocolVersion = 3;
    lRtn = ldap_set_option(ldap_session_.get(), LDAP_OPT_PROTOCOL_VERSION, &protocolVersion );
    if (lRtn != LDAP_SUCCESS) {
        MORDOR_LOG_ERROR(g_log) << "ldap_set_option() triggered error " << lRtn << " enabling LDAP 3. See MSDN documentation on ldap_set_option() for details.";
        return false;
    }

    lRtn = ldap_set_option(ldap_session_.get(), LDAP_OPT_TIMELIMIT, &query_timeout_);
    if (lRtn != LDAP_SUCCESS) {
        MORDOR_LOG_ERROR(g_log) << "ldap_set_option() triggered error " << lRtn << " setting LDAP timeout. See MSDN documentation on ldap_set_option() for details.";
        return false;
    }

    if (ldap_server_.protocol == LDAPS) {
        lRtn = ldap_set_option(ldap_session_.get(), LDAP_OPT_SSL, LDAP_OPT_ON);
        if (lRtn != LDAP_SUCCESS) {
            MORDOR_LOG_ERROR(g_log) << "ldap_set_option() triggered error " << lRtn << " set on LDAP_OPT_SSL. See MSDN documentation on ldap_set_option() for details.";
            return false;
        }
        lRtn = ldap_set_option(ldap_session_.get(), LDAP_OPT_SERVER_CERTIFICATE, &ldap_server_cert_callback);
        if (lRtn != LDAP_SUCCESS) {
            MORDOR_LOG_ERROR(g_log) << "ldap_set_option() triggered error " << lRtn << " set off LDAP_OPT_REFERRALS. See MSDN documentation on ldap_set_option() for details.";
            return false;
        }
    }

    lRtn = ldap_connect(ldap_session_.get(), NULL);
    if (lRtn != LDAP_SUCCESS) {
        MORDOR_LOG_ERROR(g_log) << "ldap_connect() triggered error " << lRtn << ", 81 means server down. Others please check MSDN.";
        return false;
    }

    return true;
}

int LdapClient::QueryLdap(std::string filter, size_t page)
{
    return 0;
}

}