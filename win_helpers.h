#pragma once

#include <string>
#include <mordor/string.h>
#include <mordor/streams/ssl.h>

namespace dpc {
#define stdstring2LPWSTR(str) const_cast<LPWSTR>((Mordor::toUtf16(str)).c_str())

bool writeRegistry(std::string key, std::string name, std::string value, std::string entropy="");
std::string readRegistry(std::string key, std::string name, std::string entropy="");
std::wstring GetEventLogDllPath();
bool AddCertificatesFromWindowsStore(X509_STORE * app_store, LPCWSTR storeName);
BOOLEAN CheckCertificateInStore(PCCERT_CONTEXT pCert, LPTSTR store_name);
std::string GetWindowsInternalVersion();
std::string GetAppVersion();
}