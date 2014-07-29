#pragma once

#include <mordor/json.h>

namespace dpc {

enum LdapProtocol {StartTLS, LDAPS, NO_SSL};
enum DeprovisionAction {NO_ACTION, SUSPEND, DELETE};

struct LdapConnectSetting {
    std::string host;
    int port;
    LdapProtocol protocol;
    std::string base_dn;
    std::string username; //bind user, these 2 are set in LDAPConnector configuration
    std::string password; //bind password
};

struct ProvisionRule {
    std::string query;
    std::string target_group;
};
struct DeprovisionRule {
    std::string query;
    DeprovisionAction action;
};

/* this class is a partial mapping from fedid sync config json schema.
 * you can check the full schema at <bifrost repo>/api/fedid/schemas/fedid-config-schema.json
 * and you can also get the idea for why we need these fields by visiting any FedID-enabled
 * partner's "Authentication Policy" page in Admin Console.
 * For LDAPConnector interesting, only "Connection Settings", "Sync Rules" and "Attributes Mapping"
 * these 3 page have values mapping here.
 */
class SyncConfig
{
public:
    typedef boost::shared_ptr<SyncConfig> ptr;
    SyncConfig(Mordor::JSON::Object& json_obj);
    ~SyncConfig(void);

    std::string PartnerId() const
    { return fedid_partner_; }
    std::string ConfigUrl() const
    { return resource_url_; }
    LdapConnectSetting LdapSetting() const
    { return ldap_setting_; }

private:
    void parseLdapSettings(const Mordor::JSON::Object& ldap_conn);
    void parseAttrMapping(const Mordor::JSON::Object& attr_mapping);
    void parseRules(const Mordor::JSON::Object& rules);

private:
    std::string resource_url_; // meta/link value
    std::string fedid_partner_; // meta/id

    LdapConnectSetting ldap_setting_;
    std::vector<ProvisionRule> engage_rules_;
    std::vector<DeprovisionRule> cancel_rules_;
    std::string name_to_mozy_username_; // ldap attr name which will map to mozy username (usual email in LDAP)
    std::string name_to_mozy_name_; // ldap attr name which will map to mozy name. (usual cn in LDAP)
    std::string name_to_mozy_external_id_; // won't change in ldap side, such as employee#
};
}