 #pragma once

//Defines used for production versions
#include "targetver.h"
#undef _WIN32_WINNT
#include <mordor/pch.h>

#include <openssl/err.h>

#include <winldap.h>
#define SECURITY_WIN32
#include <WinCrypt.h>

#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "crypt32.lib")

