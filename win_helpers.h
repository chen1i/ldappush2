#pragma once

#include <string>

#include <mordor/streams/ssl.h>

namespace dpc
{
bool writeRegistry(std::string key, std::string name, std::string value, std::string entropy="");
std::string readRegistry(std::string key, std::string name, std::string entropy="");
std::wstring GetEventLogDllPath();
bool AddCertificatesFromWindowsStore(X509_STORE * app_store, LPCWSTR storeName);
std::string GetWindowsInternalVersion();
std::string GetAppVersion();
}