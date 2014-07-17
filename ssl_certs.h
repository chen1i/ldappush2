#pragma once

#include <mordor/streams/ssl.h>

namespace dpc {

int LoadAppCertificates(X509_STORE *app_store);

}
