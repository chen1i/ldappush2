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
		("help,h", "this help mesasge")
		("partner_id,i", po::value<std::string>(), "Id of partner who enable FedID. Always required")
		("api_key,k", po::value<std::string>(), "Required during configuration. Do not use during normal operations")
		("ldap_req_timeout,m", po::value<int>()->default_value(120), "Time out seconds when talking to ldap server, default is 120 seconds")
		("ldp_page_size,w", po::value<int>()->default_value(100), "Batch size of each ldap query, default is 100 records")
		("ldap_username,u", po::value<std::string>(), "Required during configuration. Do not use during normal operations")
		("ldap_password,p", po::value<std::string>(), "Required during configuration. Do not use during normal operations")
		("show_ldap_config,l", "Optional during normal operations. True when provided")
		("bifrost_url,b", po::value<std::string>()->default_value("services.mozy.com"), "Bifrost endpoint, default is 'services.mozy.com'")
        ("ldap2_host", po::value<std::string>(), "Secondary ldap instance IP")
        ("ldap2_port", po::value<int>()->default_value(389), "Secondary ldap instance port, default is 389, only valid when ldap2_host is provided.")
        ("ldap2_username", po::value<std::string>(), "Logon name to secondary ldap instance, only valid when ldap2_host is provided.")
        ("ldap2_password", po::value<std::string>(), "Logon password to secondary ldap instance, only valid when ldap2_host is provided.")
        ("proxy_uri", po::value<std::string>(), "Optional during configuration. Use the format: 'https://proxy-server.mycorp.com:1234/' or 'https://10.167.14.116:1234/'")
		("proxy_logon_name", po::value<std::string>(), "Optional during configuration")
		("proxy_logon_password", po::value<std::string>(),"Optional during configuration")
		("test_mode,t", "Optional during normal operations. True when provided")
		("ignore_certificates,s", "Optional during normal operations, True when provided")
        ("verbose,v", "Show more detailed message. True when provided")
		("version", "Show version info")
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
    return false;
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
    {return "";}
std::string Settings::ApiKey() const
    {return "";}
std::string Settings::CurrentVersion() const
    {return "";}
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
} /*namespace dpc*/
