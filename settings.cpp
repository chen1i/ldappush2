#include "StdAfx.h"
#include "settings.h"
#include "win_helpers.h"
#include <iostream>

#include <mordor/config.h>
#include <mordor/string.h>
using namespace Mordor;

namespace dpc {

const char* Settings::encrypt_string = "DZ9o8HP4ojqw7WcT/Q23HHll77kRzI7r1grRxEUkVZg=";

Settings::Settings(int screen_width):
    desc_(screen_width, screen_width/2)
{
	desc_.add_options()
		("help,h", "this help mesasge. [C] config only. [R] normal run only. [O] optional setting.")
		("partner_id,i", po::value<std::string>(), "[C,R] Id of partner who enable FedID")
		("api_key,k", po::value<std::string>(), "[C] Partner's API key, generated in Admin Console")
		("ldap_req_timeout,m", po::value<int>()->default_value(120), "[R,O] Timeout seconds when query ldap server, default is 120 seconds")
		("ldp_page_size,w", po::value<int>()->default_value(100), "[R,O] Batch size of each ldap query, default is 100, no larger than 1000")
		("ldap_username,u", po::value<std::string>(), "[C] Logon name to AD server")
		("ldap_password,p", po::value<std::string>(), "[C] Logon password to AD server")
		("show_ldap_config,l", "[R,O] Show ldap settings. True when provided")
		("bifrost_url,b", po::value<std::string>()->default_value("https://services.mozy.com"), "[R,O] Bifrost endpoint, default is 'https://services.mozy.com'")
        ("ldap2_host", po::value<std::string>(), "[C,O] Secondary ldap instance IP")
        ("ldap2_port", po::value<int>()->default_value(389), "[C,O] Secondary ldap instance port, default is 389, only valid when ldap2_host is provided.")
        ("ldap2_username", po::value<std::string>(), "[C,O] Logon name to secondary ldap instance, only valid when ldap2_host is provided.")
        ("ldap2_password", po::value<std::string>(), "[C,O] Logon password to secondary ldap instance, only valid when ldap2_host is provided.")
        ("proxy_uri,x", po::value<std::string>(), "[C,O] Global proxy setting. format: 'https://proxy-server.mycorp.com:1234/' or 'http://10.167.14.116:1234/'")
		("proxy_logon_name", po::value<std::string>(), "[C,O] Proxy username")
		("proxy_logon_password", po::value<std::string>(),"[C,O] Proxy password")
		("test_mode,t", "[R,O] Dry run mode. True when provided")
		("ignore_certificates,s", "[C,R,O] Ignore SSL certificate checking. True when provided")
        ("verbose,v", "[C,R,O] Show more detailed message. True when provided")
		("version", "[C] Show version info and quit")
		;
}


Settings::~Settings(void)
{
}

void Settings::ShowCLIOptions()
{
    std::cout<<desc_<<std::endl;
}

static void printConfigVar(std::ostream *os, ConfigVarBase::ptr var)
{
    *os << var->name() <<" = "<<var->toString()<<std::endl;
}
int Settings::ParseCLI(int argc, char* argv[])
{
    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm_);
        po::notify(vm_);

        if (vm_.count("help")) {
            ShowCLIOptions();
            exit(0);
        }

        if (vm_.count("version")) {
            Config::visit(boost::bind(&printConfigVar, &(std::cout), _1));
        }

    } catch (...) {
        ShowCLIOptions();        
    }

    return vm_.size();
}

bool Settings::IsConfigMode()
{
    return true;
}
int Settings::PersistToRegistry()
{
    return 0;
}

std::string Settings::PartnerId() const
{
    assert(vm_.count("partner_id"));
    return vm_["partner_id"].as<std::string>();
}
std::string Settings::BifrostEndpoint() const
    {return vm_["bifrost_url"].as<std::string>();}
std::string Settings::ApiKey() const
    {return vm_["api_key"].as<std::string>();}
bool Settings::IgnoreSslCheck() const
{ return vm_.count("ignore_certificates")>0;}
std::string Settings::CurrentVersion() const
    {return GetAppVersion();}
std::string Settings::LdapHost() const
    {return "";}
int Settings::LdapPort() const
    {return 389;}
std::string Settings::LdapUser() const
    {return "";}
std::string Settings::LdapPassword() const
    {return "";}
std::string Settings::LdapBaseDN() const
    {return "";}

std::string Settings::ProxyUri() const
{
    if (vm_.count("proxy_uri")>0)
        return vm_["proxy_uri"].as<std::string>();
    else
        return "";
}
std::string Settings::ProxyUser() const
{
    if (ProxyUri().empty())
        return "";

    if (vm_.count("proxy_logon_name")>0)
        return vm_["proxy_logon_name"].as<std::string>();
    else
        return "";
}
std::string Settings::ProxyPassword() const
{
    if (ProxyUri().empty())
        return "";

    if (vm_.count("proxy_logon_password")>0)
        return vm_["proxy_logon_password"].as<std::string>();
    else
        return "";}


} /*namespace dpc*/
