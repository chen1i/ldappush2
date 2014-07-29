#include "stdafx.h"
#include "win_helpers.h"
#include <string>
#include <strsafe.h>

#include "ssl_certs.h"
#include "logger.h"

REGISTER_LOGGER("dpc:connector:win_helpers");

namespace dpc
{
static void PrintLastErrorMessage(LPTSTR lpszFunction)
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %x: %s"),
        lpszFunction, dw, lpMsgBuf);
    MORDOR_LOG_ERROR(g_log) << Mordor::toUtf8((LPCTSTR)lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}

bool WriteRegistry(std::string key, std::string name, std::string value, std::string encrypt_string)
{
    HKEY hKey;
    bool success = false;
    LONG retVal = RegCreateKeyEx(HKEY_LOCAL_MACHINE, stdstring2LPWSTR(key), 0, NULL, 0, KEY_SET_VALUE | KEY_WRITE, NULL, &hKey, NULL);
    assert(retVal == ERROR_SUCCESS);
    DATA_BLOB dataIn;
    dataIn.pbData = (PBYTE)value.c_str();
    dataIn.cbData = value.length()+1; // as per MSDN, the length should include terminating \0

    if (!encrypt_string.empty()) {
        DATA_BLOB dataOut;
        DATA_BLOB entropy;
        entropy.pbData = (PBYTE)encrypt_string.c_str();
        entropy.cbData = encrypt_string.length();
        if (CryptProtectData(&dataIn, NULL, &entropy, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &dataOut)) {
            retVal = RegSetValueEx(hKey, stdstring2LPWSTR(name), 0, REG_BINARY, (const BYTE*)dataOut.pbData, dataOut.cbData);
            success = (retVal == ERROR_SUCCESS);
            LocalFree(dataOut.pbData);
        }
    }else{
        retVal = RegSetValueEx(hKey, stdstring2LPWSTR(name), 0, REG_SZ, (const BYTE*)dataIn.pbData, dataIn.cbData);
        success = (retVal == ERROR_SUCCESS);
    }

    if (hKey)
        RegCloseKey(hKey);

    return success;
}

std::string ReadRegistry(std::string key, std::string name, std::string encrypt_string)
{
    std::string returnValue;
    HKEY hKey;
    LONG retVal = RegOpenKeyEx(HKEY_LOCAL_MACHINE, stdstring2LPWSTR(key), 0, KEY_READ, &hKey);
    assert(retVal == ERROR_SUCCESS);

    DWORD sizeOfValue=0;
    DWORD type;
    // Get the size of the value
    retVal = RegQueryValueEx(hKey, stdstring2LPWSTR(name), 0, &type, NULL, &sizeOfValue);
    assert(retVal == ERROR_SUCCESS);

    LPBYTE fieldValue = new BYTE[sizeOfValue];
    retVal = RegQueryValueEx(hKey, stdstring2LPWSTR(name), 0, &type, fieldValue, &sizeOfValue);
    assert(retVal == ERROR_SUCCESS);

    if (!encrypt_string.empty()) {
        DATA_BLOB dataIn;
        DATA_BLOB dataOut;
        DATA_BLOB entropy;
        dataIn.pbData = (PBYTE)fieldValue;
        dataIn.cbData = sizeOfValue;
        entropy.pbData = (PBYTE)encrypt_string.c_str();
        entropy.cbData = encrypt_string.length();

        if (CryptUnprotectData(&dataIn, NULL, &entropy, NULL, NULL, 0, &dataOut)) {
            returnValue = (char *)dataOut.pbData;
            LocalFree(dataOut.pbData);
        }
    }else{
        returnValue = Mordor::toUtf8(std::wstring((wchar_t*)fieldValue));
    }
    delete[] fieldValue;

    if (hKey)
        RegCloseKey(hKey);

    return returnValue;
}

std::wstring GetEventLogDllPath()
{
    TCHAR msgDllPath[1024];
    GetModuleFileName(NULL, msgDllPath, 1024);
    std::wstring path(msgDllPath);
    path.replace(path.length()-4, 4, L"Event.dll"); // xxx.exe -> xxxEvent.dll
    return path;
}

// get the machine's trusted certificates and put them into our context's cert store
bool AddCertificatesFromWindowsStore(X509_STORE *app_store, LPCWSTR storeName)
{
    HCERTSTORE hStore = CertOpenSystemStore(0, storeName);
    if(!hStore) {
        return false;
    }

    PCCERT_CONTEXT pContext = NULL;
    while (pContext = CertEnumCertificatesInStore(hStore, pContext)) {
        BIO *in = BIO_new_mem_buf(pContext->pbCertEncoded, pContext->cbCertEncoded);
        if (!in) continue;
        X509 *x509Cert = d2i_X509_bio(in, NULL);
        BIO_free(in);
        if (x509Cert) {
            if (X509_STORE_add_cert(app_store, x509Cert) != 1) {
                unsigned long err = ERR_get_error();
                if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
                    ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                    MORDOR_LOG_DEBUG(g_log) << "Cert already loaded";
                }else{
                    // This is not considered a fatal error because this cert
                    // may not be needed for communication with Mozy, just show details and continue
                    char buf[120];
                    MORDOR_LOG_WARNING(g_log) << "X509_STORE_add_cert() Failed to add machine's certificate " << ERR_error_string(err,buf);
                }
            }
            X509_free(x509Cert);
        }
    }
    CertFreeCertificateContext(pContext);
    CertCloseStore(hStore, 0);
    return true;
} // AddCertificatesFromWindowsStore()

std::string GetWindowsInternalVersion()
{
    std::string ver_txt = ReadRegistry(std::string("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
                                       std::string("CurrentVersion"),
                                       "");
    return ver_txt;
}

std::string GetAppVersion()
{
    std::string ver_txt = ReadRegistry(std::string("SOFTWARE\\Mozy\\LDAPConnector"),
                                       std::string("Version"),
                                       "");
    return ver_txt;
}

BOOLEAN CheckCertificateInStore(PCCERT_CONTEXT pCert, LPTSTR store_name)
{
    HCERTSTORE hSystemStore;
    if (hSystemStore = CertOpenSystemStore(NULL, store_name)) {
        MORDOR_LOG_DEBUG(g_log) << "The system store "<< store_name <<" is open";
    } else {
        PrintLastErrorMessage(L"CertOpenSystemStore");
        return FALSE;
    }

    PCCERT_CONTEXT pc = CertFindCertificateInStore( hSystemStore,
                                                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                    0,
                                                    CERT_FIND_ISSUER_NAME,
                                                    (const void *)(&(pCert->pCertInfo->Issuer)),
                                                    NULL);
    BOOLEAN ret = FALSE;
    if (pc != NULL) {
        ret = TRUE;
        CertFreeCertificateContext(pc);
        MORDOR_LOG_INFO(g_log) << "Certificate check return TRUE";
    } else {
        ret = FALSE;
        PrintLastErrorMessage(L"CertFindCertificateInStore");
    }
    CertCloseStore(hSystemStore, NULL);

    PCCERT_CHAIN_CONTEXT     pChainContext;
    ret = CertGetCertificateChain(NULL, pCert, NULL, NULL, NULL, CERT_CHAIN_CACHE_END_CERT, NULL, &pChainContext);
    return ret;
}
}