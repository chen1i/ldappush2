#include "StdAfx.h"
#include "bifrost_client.h"

namespace dpc {
BifrostClient::BifrostClient(std::string partner_id, std::string svc_endpoint)
{
}

BifrostClient::~BifrostClient(void)
{
}

AuthorizationHeader BifrostClient::SvcAuthenticate()
{
    return "NOT A VALID TOKEN";
}
    
SyncConfig BifrostClient::SvcGetSyncConfig()
{
    Mordor::JSON::Object empty;
    return empty;
}
    
JobId BifrostClient::SubmitSyncData()
{
    return "INVALID JOB ID";
}

bool BifrostClient::CheckApiKey(std::string key_txt)
{
    return true;
}
int BifrostClient::ReportVersion(std::string version_txt)
{
    return 0;
}
    
int BifrostClient::CheckLatestClientVersion()
{
    return 0;
}
}