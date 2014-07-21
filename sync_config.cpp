#include "StdAfx.h"
#include "sync_config.h"

#include <boost/lexical_cast.hpp>
#include "logger.h"

namespace dpc {

REGISTER_LOGGER("dpc:connector:sync_config");

SyncConfig::SyncConfig(Mordor::JSON::Object& json_obj)
{
    using namespace Mordor::JSON;
    try {
        Value::const_iterator p = json_obj.find("items");
        Array arr_snippet = boost::get<Array>(p->second);
        Array::const_iterator item_element = arr_snippet.begin(); //items is an array, but normally it has only one element.
        if (item_element != arr_snippet.end()) {// Could be an empty array.
            p = item_element->find("data");
            Object data = boost::get<Object>(p->second);
            p = data.find("partner_id");
            fedid_partner_ = boost::get<std::string>(p->second);

            p = data.find("ad_connection");
            Object ldap_conn = boost::get<Object>(p->second);
            parseLdapSettings(ldap_conn);

            p = data.find("attr_mapping");
            Object attr_mapping = boost::get<Object>(p->second);
            parseAttrMapping(attr_mapping);

            p= data.find("rules");
            Object rules = boost::get<Object>(p->second);
            parseRules(rules);

            p = item_element->find("meta");
            Object meta = boost::get<Object>(p->second);
            p = meta.find("link");
            resource_url_ = boost::get<std::string>(p->second);
        }
    } catch (...) {
        MORDOR_LOG_ERROR(g_log) << "Parsing sync_config error, dumping raw JSON: " << json_obj;
    }
}

void SyncConfig::parseLdapSettings(const Mordor::JSON::Object& ldap_conn)
{
    using namespace Mordor::JSON;

    Value::const_iterator p = ldap_conn.find("host");
    ldap_setting_.host = boost::get<std::string>(p->second);
    p = ldap_conn.find("port");
    ldap_setting_.port = (int)boost::get<long long>(p->second);

    p = ldap_conn.find("ssl");
    std::string sslString = boost::get<std::string>(p->second);
    if (sslString == "false")
        ldap_setting_.protocol = NO_SSL;
    else if (sslString == "starttls")
        ldap_setting_.protocol = StartTLS;
    else if (sslString == "ldaps")
        ldap_setting_.protocol = LDAPS;
    else {
        MORDOR_LOG_WARNING(g_log) << "No SSL setting in sync config, will use plain LDAP";
        ldap_setting_.protocol = NO_SSL;
    }

    p = ldap_conn.find("base_dn");
    ldap_setting_.base_dn = boost::get<std::string>(p->second);
}

void SyncConfig::parseAttrMapping(const Mordor::JSON::Object& attr_mapping)
{
    using namespace Mordor::JSON;
    // ldap must specify which attr will map to 'name' and 'username' in Mozy.
    Object::const_iterator p = attr_mapping.find("name");
    if (p!=attr_mapping.end())
        name_to_mozy_name_ = boost::get<std::string>(p->second);
    else {
        MORDOR_LOG_WARNING(g_log) << "No LDAP attribute mapping to Mozy 'name', will use 'CN' by default";
        name_to_mozy_name_ = "cn";
    }

    p = attr_mapping.find("username");
    if (p!=attr_mapping.end())
        name_to_mozy_username_ = boost::get<std::string>(attr_mapping.find("username")->second);
    else {
        MORDOR_LOG_WARNING(g_log) << "No LDAP attribute mapping to Mozy 'username', will use 'mail' by default";    
        name_to_mozy_username_ = "mail";
    }
    // but it's optional to specify which attr is immutable in ldap, which usually map to 'external_id' in Mozy
    p = attr_mapping.find("immutable_attribute");
    if (p!=attr_mapping.end()) {
        name_to_mozy_external_id_ = boost::get<std::string>(p->second);
        MORDOR_LOG_INFO(g_log) << "LDAP attribute "<<name_to_mozy_external_id_<<" maps to Mozy 'external_id'";
    }else
        name_to_mozy_external_id_ = "";
}

void SyncConfig::parseRules(const Mordor::JSON::Object& rules)
{
    using namespace Mordor::JSON;
    // Get the 'deprovision' rules.
    Object::const_iterator p = rules.find("deprovision");
    if (p != rules.end()) {
        Array arr_depr = boost::get<Array>(p->second);
        for (Array::const_iterator it = arr_depr.begin(); it != arr_depr.end(); ++it) {
            DeprovisionRule rule;

            Value::const_iterator q = it->find("query");
            rule.query = boost::get<std::string>(q->second);

            q = it->find("action");
            std::string action = boost::get<std::string>(q->second);
            if (action == "take_no_action")
                rule.action = NO_ACTION;
            else if (action == "delete")
                rule.action = DELETE;
            else if (action == "suspend")
                rule.action = SUSPEND;
            else {
                MORDOR_LOG_WARNING(g_log) << "Fallback to 'take_no_action' for unknown deprovision action: "<<action;
                rule.action = NO_ACTION;
            }

            cancel_rules_.push_back(rule);
        }
    } else {
        MORDOR_LOG_INFO(g_log) << "This partner has no deprovision rule";
    }

    // Get the 'provision' rules.
    p = rules.find("provision");
    if (p != rules.end()) {
        Array arr_prov = boost::get<Array>(p->second);
        for (Array::const_iterator it = arr_prov.begin(); it != arr_prov.end(); ++it) {
            ProvisionRule rule;

            Value::const_iterator q = it->find("query");
            rule.query = boost::get<std::string>(q->second);

            q = it->find("user_group");
            rule.target_group = boost::lexical_cast<std::string>(boost::get<long long>(q->second));

            engage_rules_.push_back(rule);
        }
    } else {
        MORDOR_LOG_INFO(g_log) << "This partner has no provision rule";
    }

    MORDOR_LOG_INFO(g_log) << "Getting LDAP configuration from servers succeeded.";
}

SyncConfig::~SyncConfig(void)
{
}
} // namespace dpc