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
    /* TODO: decent certificate checking needed.
    * But now the kludge is just ignore checking and return TRUE.
    * It's unsafe but since Net::Ldap in Ruby gem are also ignore checking that makes me feel less guilty.
    */
    return TRUE;
    //if (CheckCertificateInStore(pServerCert, L"CA")
    //    ||CheckCertificateInStore(pServerCert, L"ROOT"))
    //    return TRUE;
    //else
    //    return FALSE;
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

    if (ldap_server_.protocol == StartTLS) {
        lRtn = ldap_set_option(ldap_session_.get(), LDAP_OPT_SERVER_CERTIFICATE, &ldap_server_cert_callback);
        if (lRtn != LDAP_SUCCESS) {
            MORDOR_LOG_ERROR(g_log) << "ldap_set_option() triggered error " << lRtn << " set off LDAP_OPT_REFERRALS. See MSDN documentation on ldap_set_option() for details.";
            return false;
        }
        ULONG errorReturn=0;
        LDAPMessage error_msg;
        LDAPMessage* p = &error_msg;
        lRtn = ldap_start_tls_s(ldap_session_.get(), &errorReturn, &p, NULL, NULL);
        if (lRtn != LDAP_SUCCESS) {
            if (lRtn == LDAP_UNWILLING_TO_PERFORM) {
                MORDOR_LOG_ERROR(g_log) << "LDAP_UNWILLING_TO_PERFORM returned when start TLS";
            } else {
                MORDOR_LOG_ERROR(g_log) << "LDAP_OTHER returned when start TLS, server error code is "<<error_msg.lm_returncode;
            }
            return false;
        }else{
            MORDOR_LOG_INFO(g_log) << "Start TLS on port 389";
        }
    } // enable TLS

    lRtn = ldap_bind_s(ldap_session_.get(), stdstring2LPWSTR(ldap_server_.username), stdstring2LPWSTR(ldap_server_.password), LDAP_AUTH_SIMPLE);
    if (lRtn != LDAP_SUCCESS) {
        MORDOR_LOG_ERROR(g_log) << "ldap_bind_s() triggered error " << lRtn << " See MSDN documentation on ldap_bind_s() for details.";
        return false;
    }
    MORDOR_LOG_DEBUG(g_log) << "ldap_bind_s success";
    return true;
}

int LdapClient::QueryLdap(std::string filter, size_t page)
{
    return 0;
}

}