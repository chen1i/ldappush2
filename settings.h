#pragma once

#include <boost/program_options.hpp>

namespace po=boost::program_options;

namespace dpc {

class Settings
{
public:
    Settings(int screen_width=200);
    ~Settings(void);

    void ShowCLIOptions();
    int ParseCLI(int argc, char* argv[]);
    bool IsConfigMode();
    int PersistToRegistry();

    //getters
    std::string PartnerId() const;
    std::string BifrostEndpoint() const;
    std::string ApiKey() const;
    bool IgnoreSslCheck() const;
    std::string CurrentVersion() const;
    int LdapQueryTimeout() const;
    int LdapPageSize() const;
    std::string LdapHost() const;
    int LdapPort() const;
    std::string LdapUser() const;
    std::string LdapPassword() const;
    std::string LdapBaseDN() const;
    std::string ProxyUri() const;
    std::string ProxyUser() const;
    std::string ProxyPassword() const;

private:
    po::options_description desc_;
    po::variables_map vm_;
    static const char *encrypt_string;
};
}
