#include "StdAfx.h"
#include "bifrost_client.h"
#include "logger.h"

//#include <mordor/http/auth.h>
#include <mordor/http/broker.h>
#include <mordor/http/client.h>
#include <mordor/streams/std.h>
#include <mordor/streams/memory.h>
#include <mordor/streams/transfer.h>

REGISTER_LOGGER("dpc:connector:bifrost");

namespace dpc {
BifrostClient::BifrostClient(std::string partner_id, std::string key_text, std::string svc_address):
    partner_id_(partner_id),
    api_key_(key_text)
{
    auth_token_ = "";
    root_uri_ = svc_address; //convert string to a URI obj.
    io_mgr_.reset(new Mordor::IOManager());
}

BifrostClient::~BifrostClient(void)
{
}

BifrostClient::AuthorizationHeader BifrostClient::SvcAuthenticate(bool force_new)
{
    authenticate();
    return auth_token_;
}
    
BifrostClient::SyncConfig BifrostClient::SvcGetSyncConfig()
{
    Mordor::JSON::Object empty;
    return empty;
}
    
BifrostClient::JobId BifrostClient::SubmitSyncData()
{
    return "INVALID JOB ID";
}

bool BifrostClient::CheckApiKey()
{
    //authenticate();
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

static boost::shared_ptr<Mordor::JSON::Value> parseJsonStream( boost::shared_ptr<Mordor::Stream> stream)
{
    boost::shared_ptr<Mordor::JSON::Value> json(new Mordor::JSON::Value());
    Mordor::JSON::Parser parser(*json);
    parser.run(stream);
    assert(parser.final());
    assert(!parser.error());
    return json;
}

template <class T>
static T getJsonValue( boost::shared_ptr< Mordor::JSON::Value > json, const char *fields)
{
    Mordor::JSON::Object rootObj = boost::get<Mordor::JSON::Object>(*json);
    Mordor::JSON::Value::const_iterator itKeyLookup = rootObj.find(fields);
    T retValue = boost::get<T>(itKeyLookup->second);
    return retValue;
}

std::string BifrostClient::authenticate()
{
    MORDOR_LOG_INFO(g_log) << "Getting auth token ...";

    Mordor::HTTP::Request rh;
    rh.entity.extension["Api-Key"] = api_key_;
    Mordor::HTTP::ClientRequest::ptr request = makeClientRequestObj(rh, AUTH_PATH);
    
    if (request->response().status.status == Mordor::HTTP::OK && request->hasResponseBody()) {

        boost::shared_ptr<Mordor::JSON::Value> root = parseJsonStream(request->responseStream());

        auth_token_ = getJsonValue<std::string>(root, "token_type");
        auth_token_.append(" ");
        std::string tokenString = getJsonValue<std::string>(root, "token");
        auth_token_.append(tokenString);

        MORDOR_LOG_INFO(g_log) << "Request auth token succeed";
        return tokenString;
    }else{
        MORDOR_LOG_ERROR(g_log) << "Request auth token failed ";
        return "";
    }
}

Mordor::HTTP::ClientRequest::ptr BifrostClient::makeClientRequestObj(Mordor::HTTP::Request& rh, std::string path)
{
    Mordor::URI svcEndpoint = root_uri_;
    svcEndpoint.path.append(path);

    Mordor::HTTP::RequestBrokerOptions options;
    options.ioManager = io_mgr_.get();
    Mordor::HTTP::RequestBroker::ptr rb = Mordor::HTTP::createRequestBroker(options).first;

    rh.requestLine.uri = svcEndpoint;
    rh.request.host = svcEndpoint.authority.host();
    rh.entity.extension["Accept"] = "application/vnd.mozy.bifrost+json;v=1";

    return rb->request(rh);
}
}