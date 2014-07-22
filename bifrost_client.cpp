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

static void writeBody(Mordor::HTTP::ClientRequest::ptr r, const std::string &body)
{
    r->requestStream()->write(body.c_str(), body.size());
    r->requestStream()->close();
}
int BifrostClient::ReportVersion(const std::string version_txt)
{
    MORDOR_LOG_INFO(g_log) << "Begin to update connector version to Admin Console";
    Mordor::HTTP::Request rh;
    Mordor::HTTP::RequestBroker::ptr rb = makeClientRequestObj(rh, REGISTER_PATH + partner_id_, Mordor::HTTP::PUT);
    
    // providing register json
    Mordor::JSON::Object register_json;
    register_json["partner_id"] = boost::lexical_cast<long long>(partner_id_);
    register_json["version"] = version_txt;
    register_json["os"] = std::string("windows");
    register_json["os_version"] = GetWindowsInternalVersion();

    std::ostringstream oss;
    oss<<register_json;
    std::string body = oss.str();
    rh.entity.contentLength = body.size();

    Mordor::HTTP::ClientRequest::ptr request = rb->request(rh, false, boost::bind(&writeBody, _1, boost::cref(body)));

    Mordor::HTTP::Status status_code = request->response().status.status;
    if (status_code == Mordor::HTTP::CREATED || status_code == Mordor::HTTP::OK) {
        MORDOR_LOG_INFO(g_log) << "Update connector version succeeded";
    }else{
        MORDOR_LOG_WARNING(g_log) << "Update connector version failed: status code = "<<status_code;
    }
    return (int)status_code;
}

//check if the version of the connector is active, deprecated or active
//return: 0 - active, -1 - deprecated, -2 - outdated
int BifrostClient::CheckLatestClientVersion(const std::string curr_version)
{
    using namespace Mordor;
    MORDOR_LOG_INFO(g_log) << "Begin to check latest version from Admin Console";
    HTTP::Request rh;
    HTTP::RequestBroker::ptr rb = makeClientRequestObj(rh, VERSION_PATH + curr_version+"_windows");

    HTTP::ClientRequest::ptr request = rb->request(rh);

    HTTP::Status status_code = request->response().status.status;
    if (status_code != HTTP::OK) {
        MORDOR_LOG_WARNING(g_log) << "Check connector version failed, status code is "<<status_code;
    }else{
        // this API will return a JSON as checking result
        if(!request->hasResponseBody()) {
            MORDOR_LOG_WARNING(g_log) << "Check connector version return 200, but w/o body";
            return 0;
        }

        MORDOR_LOG_INFO(g_log) << "Check connector version succeeded";
        boost::shared_ptr<Mordor::JSON::Value> root = parseJsonStream(request->responseStream());
        JSON::Object::const_iterator p = root->find("items");
        JSON::Array arr_item = boost::get<JSON::Array>(p->second);
        JSON::Array::const_iterator q = arr_item.begin();
        if(q != arr_item.end()) {
            p = q->find("data");
            JSON::Object data = boost::get<JSON::Object>(p->second);
            p = data.find("status");
            std::string status = boost::get<std::string>(p->second);

            if (status == "deprecated") {
                MORDOR_LOG_ERROR(g_log) << "This connector version is no longer supported. Please update it";
                sendConnectorVersionEvent(-2);
                return -2;
            } else if (status == "to-be-deprecated") {
                MORDOR_LOG_WARNING(g_log) << "This connector is deprecated. You are suggested to upgrade it";
                sendConnectorVersionEvent(-1);
                return -1;
            } else {
                MORDOR_LOG_INFO(g_log) << "Version check OK";
            }
        } else {
            MORDOR_LOG_ERROR(g_log) << "Cannot find version check result for this connector";
            return 0;
        }
    }
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

void BifrostClient::sendConnectorVersionEvent(int event_type)
{
    MORDOR_LOG_INFO(g_log) << "Begin to send connector version outdated/deprecated notification";
    Mordor::HTTP::Request rh;
    Mordor::HTTP::RequestBroker::ptr rb = makeClientRequestObj(rh, VERSION_ALERT_PATH, Mordor::HTTP::POST);

    // providing parameter json
    Mordor::JSON::Object param_json, tmp_json;
    boost::posix_time::ptime now(boost::posix_time::second_clock::universal_time());
    std::string now_str = to_iso_extended_string(now);

    param_json["timestamp"] = now_str;
    if (event_type == -1)
        param_json["type"] = std::string("com.mozy.fedid.connector.version.to-be-deprecated");
    else
        param_json["type"] = std::string("com.mozy.fedid.connector.version.deprecated");
    tmp_json["entity_type"] = std::string("partner");
    tmp_json["entity_id"] = boost::lexical_cast<long long>(partner_id_);
    param_json["source"] = tmp_json;

    std::ostringstream oss;
    oss<<param_json;
    std::string body = oss.str();
    rh.entity.contentLength = body.size();

    Mordor::HTTP::ClientRequest::ptr request = rb->request(rh, false, boost::bind(&writeBody, _1, boost::cref(body)));

    Mordor::HTTP::Status status_code = request->response().status.status;
    if (status_code != Mordor::HTTP::CREATED) {
        MORDOR_LOG_ERROR(g_log) << "Sending connector version outdated/deprecated notification failed, POST return " << status_code;
    } else {
        MORDOR_LOG_INFO(g_log) << "Sending connector version outdated/deprecated notification succeeded";
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

Mordor::HTTP::RequestBroker::ptr BifrostClient::makeClientRequestObj(Mordor::HTTP::Request& rh, const std::string path, const std::string method)
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
        MORDOR_LOG_DEBUG(g_log) << "setting proxy info "<<proxy_uri_;
        options.getProxyCredentialsDg = boost::bind(&authProxy, _2, _3, _5, _6, proxy_user_, proxy_password_);
        options.proxyRequestBroker = Mordor::HTTP::createRequestBroker(options).first;
        options.proxyForURIDg = boost::bind(&setProxy, _1, proxy_uri_);
    }

    options.ioManager = io_mgr_.get();
    Mordor::HTTP::RequestBroker::ptr rb = Mordor::HTTP::createRequestBroker(options).first;

    rh.requestLine.uri = svcEndpoint;
    rh.requestLine.method = method;
    rh.request.host = svcEndpoint.authority.host();
    rh.entity.extension["Accept"] = "application/vnd.mozy.bifrost+json;v=1";
    rh.entity.extension["Content-Type"] = "application/json";
    rh.entity.extension["User-Agent"] = "LDAPConnector /1.4";
    if (path == AUTH_PATH)
        rh.entity.extension["Api-Key"] = api_key_;
    else
        rh.entity.extension["Authorization"] = auth_token_;

    return rb;
}
}