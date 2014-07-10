#include "stdafx.h"
#include "win_helpers.h"

// Get Win7+ APIs
#define _WIN32_WINNT 0x0601
// Don't include tons of crap from windows.h
#define WIN32_LEAN_AND_MEAN
// Define this so security.h works
#define SECURITY_WIN32
#include <Windows.h>
#include <WinCrypt.h>

#include <mordor/string.h>
#include <cassert>

#pragma comment(lib, "crypt32.lib")

namespace dpc
{
#define stdstring2LPWSTR(str) const_cast<LPWSTR>((Mordor::toUtf16(str)).c_str())


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
        returnValue = (char *)fieldValue;
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

}