#include "StdAfx.h"
#include "bifrost_client.h"

#include <cassert>
#include <mordor/http/broker.h>
#include <mordor/http/client.h>
#include <mordor/http/proxy.h>
#include <mordor/streams/std.h>

#include "sync_config.h"
#include "logger.h"
#include "settings.h"
#include "ssl_certs.h"
#include "win_helpers.h"

REGISTER_LOGGER("dpc:connector:bifrost");

namespace dpc {
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
static T getJsonValue(boost::shared_ptr< Mordor::JSON::Value > json, const char *fields)
{
    Mordor::JSON::Object rootObj = boost::get<Mordor::JSON::Object>(*json);
    Mordor::JSON::Value::const_iterator itKeyLookup = rootObj.find(fields);
    T retValue = boost::get<T>(itKeyLookup->second);
    return retValue;
}

BifrostClient::BifrostClient(Settings& all_options):
    partner_id_(all_options.PartnerId()),
    api_key_(all_options.ApiKey()),
    check_ssl_(!all_options.IgnoreSslCheck()),
    proxy_uri_(all_options.ProxyUri()),
    proxy_user_(all_options.ProxyUser()),
    proxy_password_(all_options.ProxyPassword())
{
    auth_token_ = "";
    root_uri_ = all_options.BifrostEndpoint(); //convert string to a URI obj.

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
    if (auth_token_.empty() || force_new)
        authenticate();

    // the auth_token_ normally expired after 1800 sec. should longer enough
    // for calling Bifrost.
    return auth_token_;
}
    
Mordor::JSON::Object BifrostClient::SvcGetSyncConfigJson()
{
    Mordor::JSON::Object retJson;
    MORDOR_LOG_INFO(g_log) << "Getting sync config ...";

    Mordor::HTTP::Request rh;
    Mordor::HTTP::RequestBroker::ptr rb = makeClientRequestObj(rh, SYNCCONFIG_PATH);

    Mordor::HTTP::ClientRequest::ptr request = rb->request(rh);

    if (request->response().status.status == Mordor::HTTP::OK && request->hasResponseBody()) {

        boost::shared_ptr<Mordor::JSON::Value> root = parseJsonStream(request->responseStream());

        retJson = boost::get<Mordor::JSON::Object>(*root);

        MORDOR_LOG_INFO(g_log) << "Get sync config succeed";
    }else{
        MORDOR_LOG_ERROR(g_log) << "Get sync config failed ";
    }
    return retJson;
}
    
BifrostClient::JobId BifrostClient::SubmitSyncData()
{
    return "INVALID JOB ID";
}

bool BifrostClient::CheckApiKey()
{
    if (auth_token_.empty())
        authenticate();

    std::string pid;
    SyncConfig sync_config(SvcGetSyncConfigJson());

    return sync_config.PartnerId() == partner_id_;
}
int BifrostClient::ReportVersion(std::string version_txt)
{
    return 0;
}
    
int BifrostClient::CheckLatestClientVersion()
{
    return 0;
}

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

std::string BifrostClient::authenticate()
{
    MORDOR_LOG_INFO(g_log) << "Getting auth token ...";

    Mordor::HTTP::Request rh;
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

static bool authProxy(Mordor::HTTP::ClientRequest::ptr priorRequest, std::string& scheme, std::string& username, std::string& password, const std::string c_user, const std::string c_password)
{
    if (!priorRequest)
        return false;
    username = c_user;
    password = c_password;
    const Mordor::HTTP::ChallengeList &challengeList = priorRequest->response().response.proxyAuthenticate;
#ifdef WINDOWS
    if (Mordor::HTTP::isAcceptable(challengeList, "Negotiate")) {
        scheme = "Negotiate";
        return true;
    }
    if (Mordor::HTTP::isAcceptable(challengeList, "NTLM")) {
        scheme = "NTLM";
        return true;
    }
#endif
    if (Mordor::HTTP::isAcceptable(challengeList, "Digest")) {
        scheme = "Digest";
        return true;
    }
    if (Mordor::HTTP::isAcceptable(challengeList, "Basic")) {
        scheme = "Basic";
        return true;
    }
    return false;
}

// This method is called by Mordor for each request, to get proxy information.
static std::vector<Mordor::URI> setProxy(const Mordor::URI &dest, const std::string c_proxy)
{
    std::vector<Mordor::URI> proxies;

#ifdef WINDOWS
    // One side affect of the following is to convert the proxy scheme as specified to the scheme of the
    // host URI passed in. So if someone messes up and specifies an 'http' proxy, this will fix things up
    // by changing it to 'https'.
    proxies = Mordor::HTTP::proxyFromList(dest, c_proxy);
#else
    // TODO: If we were to support proxies on linux we
    // would need to do something here. Load them from a config file for example
    return std::vector<URI>();
#endif
    return proxies;
} //proxyForUriDg()

Mordor::HTTP::RequestBroker::ptr BifrostClient::makeClientRequestObj(Mordor::HTTP::Request& rh, std::string path)
{
    Mordor::URI svcEndpoint = root_uri_;
    svcEndpoint.path.append(path);

    Mordor::HTTP::RequestBrokerOptions options;

    // SSL options
    if (check_ssl_ && ssl_ctx_.get()) {
        options.verifySslCertificateHost = options.verifySslCertificate = true;
        options.sslCtx = ssl_ctx_.get();
    }else{
        options.verifySslCertificateHost = options.verifySslCertificate = false;
    }

    // proxy options
    if (!proxy_uri_.empty()) {
        MORDOR_LOG_INFO(g_log) << "setting proxy info "<<proxy_uri_;
        options.getProxyCredentialsDg = boost::bind(&authProxy, _2, _3, _5, _6, proxy_user_, proxy_password_);
        options.proxyRequestBroker = Mordor::HTTP::createRequestBroker(options).first;
        options.proxyForURIDg = boost::bind(&setProxy, _1, proxy_uri_);
    }

    options.ioManager = io_mgr_.get();
    Mordor::HTTP::RequestBroker::ptr rb = Mordor::HTTP::createRequestBroker(options).first;

    rh.requestLine.uri = svcEndpoint;
    rh.request.host = svcEndpoint.authority.host();
    rh.entity.extension["Accept"] = "application/vnd.mozy.bifrost+json;v=1";
    rh.entity.extension["Content-Type"] = "application/json";
    rh.entity.extension["User-Agent"] = "FedIDPushClient /1.0";
    if (path == AUTH_PATH)
        rh.entity.extension["Api-Key"] = api_key_;
    else
        rh.entity.extension["Authorization"] = auth_token_;

    return rb;
}


}