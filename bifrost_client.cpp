#include "StdAfx.h"
#include "bifrost_client.h"

#include <cassert>
#include <mordor/http/broker.h>
#include <mordor/http/client.h>
#include <mordor/streams/std.h>

#include "logger.h"
#include "ssl_certs.h"
#include "win_helpers.h"

REGISTER_LOGGER("dpc:connector:bifrost");

namespace dpc {
void BifrostClient::initSSLCertificates()
{
    ssl_ctx_.reset(SSL_CTX_new(SSLv23_client_method()), &SSL_CTX_free);
    X509_STORE *certstore = SSL_CTX_get_cert_store(ssl_ctx_.get());
    assert(certstore);

    LoadAppCertificates(certstore);
#ifdef WINDOWS
    if (! AddCertificatesFromWindowsStore(certstore, L"ROOT"))
        MORDOR_LOG_WARNING(g_log) << "Failed to load machine's root certificates";
    if (! AddCertificatesFromWindowsStore(certstore, L"CA"))
        MORDOR_LOG_WARNING(g_log) << "Failed to load machine's intermediate certificates";
#endif

} // initSSLCertificates()


BifrostClient::BifrostClient(std::string partner_id, std::string key_text, std::string svc_address, bool ignore_ssl_cert):
    partner_id_(partner_id),
    api_key_(key_text),
    check_ssl_(!ignore_ssl_cert)
{
    auth_token_ = "";
    root_uri_ = svc_address; //convert string to a URI obj.
    //initial ssl_ctx_ if necessary
    if (root_uri_.scheme() == "https" || !root_uri_.schemeDefined()) {
        initSSLCertificates();
    }else{
        ssl_ctx_.reset();
    }
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
    Mordor::HTTP::RequestBroker::ptr rb = makeClientRequestObj(rh, AUTH_PATH);
    
    Mordor::HTTP::ClientRequest::ptr request = rb->request(rh);
    
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

Mordor::HTTP::RequestBroker::ptr BifrostClient::makeClientRequestObj(Mordor::HTTP::Request& rh, std::string path)
{
    Mordor::URI svcEndpoint = root_uri_;
    svcEndpoint.path.append(path);

    Mordor::HTTP::RequestBrokerOptions options;
    if (check_ssl_ && ssl_ctx_.get()) {
        options.verifySslCertificateHost = options.verifySslCertificate = true;
        options.sslCtx = ssl_ctx_.get();
    }else{
        options.verifySslCertificateHost = options.verifySslCertificate = false;
    }
    options.ioManager = io_mgr_.get();
    Mordor::HTTP::RequestBroker::ptr rb = Mordor::HTTP::createRequestBroker(options).first;

    rh.requestLine.uri = svcEndpoint;
    rh.request.host = svcEndpoint.authority.host();
    rh.entity.extension["Accept"] = "application/vnd.mozy.bifrost+json;v=1";

    return rb;
}
}