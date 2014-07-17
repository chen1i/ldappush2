#include "stdafx.h"
#include "ssl_certs.h"

/*
** This certificate data and comment is copied from the Sync client source(THANK YOU!).
** I suspect that it is only really needed for Linux installations because Windows has an
** API for getting this information. However there is no harm in having duplicates of these
** certificates, so I am leaving this in for all platforms just to be super safe.
*/
// this data comes from kalypso.git/kalypso/trustedcertificates.pem.
// kalypso uses a few hundred lines of custom code to read the pem
// file as a binary resource in backup.dll; macmozy actually installs
// the pem file in its application bundle.  I've decided here to
// take a portable approach with no installer dependencies...
// since certs are embedded in the executable (not brandable)
// and not updated frequently (maybe every other year), I figure
// this approach is more than adequate.
static const char *sslCertificates[] = {
    // ValiCert Class 3 Policy Validation Authority => RSA Public Root CA v1 => RSA Corporate => RSA Corporate Server CA => *.mozypro.com
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC5zCCAlACAQEwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0\n"
    "IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAz\n"
    "BgNVBAsTLFZhbGlDZXJ0IENsYXNzIDMgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9y\n"
    "aXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG\n"
    "9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTk5MDYyNjAwMjIzM1oXDTE5MDYy\n"
    "NjAwMjIzM1owgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0IFZhbGlkYXRpb24gTmV0d29y\n"
    "azEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENs\n"
    "YXNzIDMgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRw\n"
    "Oi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0BCQEWEWluZm9AdmFsaWNl\n"
    "cnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDjmFGWHOjVsQaBalfD\n"
    "cnWTq8+epvzzFlLWLU2fNUSoLgRNB0mKOCn1dzfnt6td3zZxFJmP3MKS8edgkpfs\n"
    "2Ejcv8ECIMYkpChMMFp2bbFc893enhBxoYjHW5tBbcqwuI4V7q0zK89HBFx1cQqY\n"
    "JJgpp0lZpd34t0NiYfPT4tBVPwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAFa7AliE\n"
    "Zwgs3x/be0kz9dNnnfS0ChCzycUs4pJqcXgn8nCDQtM+z6lU9PHYkhaM0QTLS6vJ\n"
    "n0WuPIqpsHEzXcjFV9+vqDWzf4mH6eglkrh/hXqu1rweN1gqZ8mRzyqBPu3GOd/A\n"
    "PhmcGcwTTYJBtYze4D1gCCAPRX5ron+jjBXu\n"
    "-----END CERTIFICATE-----\n",

    // Entrust.net Secure Server Certification Authority => DigiCert Global CA => *.mozypro.com
    "-----BEGIN CERTIFICATE-----\n"
    "MIIE2DCCBEGgAwIBAgIEN0rSQzANBgkqhkiG9w0BAQUFADCBwzELMAkGA1UEBhMC\n"
    "VVMxFDASBgNVBAoTC0VudHJ1c3QubmV0MTswOQYDVQQLEzJ3d3cuZW50cnVzdC5u\n"
    "ZXQvQ1BTIGluY29ycC4gYnkgcmVmLiAobGltaXRzIGxpYWIuKTElMCMGA1UECxMc\n"
    "KGMpIDE5OTkgRW50cnVzdC5uZXQgTGltaXRlZDE6MDgGA1UEAxMxRW50cnVzdC5u\n"
    "ZXQgU2VjdXJlIFNlcnZlciBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw05OTA1\n"
    "MjUxNjA5NDBaFw0xOTA1MjUxNjM5NDBaMIHDMQswCQYDVQQGEwJVUzEUMBIGA1UE\n"
    "ChMLRW50cnVzdC5uZXQxOzA5BgNVBAsTMnd3dy5lbnRydXN0Lm5ldC9DUFMgaW5j\n"
    "b3JwLiBieSByZWYuIChsaW1pdHMgbGlhYi4pMSUwIwYDVQQLExwoYykgMTk5OSBF\n"
    "bnRydXN0Lm5ldCBMaW1pdGVkMTowOAYDVQQDEzFFbnRydXN0Lm5ldCBTZWN1cmUg\n"
    "U2VydmVyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGdMA0GCSqGSIb3DQEBAQUA\n"
    "A4GLADCBhwKBgQDNKIM0VBuJ8w+vN5Ex/68xYMmo6LIQaO2f55M28Qpku0f1BBc/\n"
    "I0dNxScZgSYMVHINiC3ZH5oSn7yzcdOAGT9HZnuMNSjSuQrfJNqc1lB5gXpa0zf3\n"
    "wkrYKZImZNHkmGw6AIr1NJtl+O3jEP/9uElY3KDegjlrgbEWGWG5VLbmQwIBA6OC\n"
    "AdcwggHTMBEGCWCGSAGG+EIBAQQEAwIABzCCARkGA1UdHwSCARAwggEMMIHeoIHb\n"
    "oIHYpIHVMIHSMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRW50cnVzdC5uZXQxOzA5\n"
    "BgNVBAsTMnd3dy5lbnRydXN0Lm5ldC9DUFMgaW5jb3JwLiBieSByZWYuIChsaW1p\n"
    "dHMgbGlhYi4pMSUwIwYDVQQLExwoYykgMTk5OSBFbnRydXN0Lm5ldCBMaW1pdGVk\n"
    "MTowOAYDVQQDEzFFbnRydXN0Lm5ldCBTZWN1cmUgU2VydmVyIENlcnRpZmljYXRp\n"
    "b24gQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMCmgJ6AlhiNodHRwOi8vd3d3LmVu\n"
    "dHJ1c3QubmV0L0NSTC9uZXQxLmNybDArBgNVHRAEJDAigA8xOTk5MDUyNTE2MDk0\n"
    "MFqBDzIwMTkwNTI1MTYwOTQwWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAU8Bdi\n"
    "E1U9s/8KAGv7UISX8+1i0BowHQYDVR0OBBYEFPAXYhNVPbP/CgBr+1CEl/PtYtAa\n"
    "MAwGA1UdEwQFMAMBAf8wGQYJKoZIhvZ9B0EABAwwChsEVjQuMAMCBJAwDQYJKoZI\n"
    "hvcNAQEFBQADgYEAkNwwAvpkdMKnCqV8IY00F6j7Rw7/JXyNEwr75Ji174z4xRAN\n"
    "95K+8cPV1ZVqBLssziY2ZcgxxufuP+NXdYR6Ee9GTxj005i7qIcyunL2POI9n9cd\n"
    "2cNgQ4xYDiKWL2KjLB+6rQXvqzJ4h6BUcxm1XAX5Uj5tLUUL9wqT6u0G+bI=\n"
    "-----END CERTIFICATE-----\n",

    // VeriSign/RSA Secure Server CA => mozy.com
    "-----BEGIN CERTIFICATE-----\n"
    "MIICNDCCAaECEAKtZn5ORf5eV288mBle3cAwDQYJKoZIhvcNAQECBQAwXzELMAkG\n"
    "A1UEBhMCVVMxIDAeBgNVBAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYD\n"
    "VQQLEyVTZWN1cmUgU2VydmVyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk0\n"
    "MTEwOTAwMDAwMFoXDTEwMDEwNzIzNTk1OVowXzELMAkGA1UEBhMCVVMxIDAeBgNV\n"
    "BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2Vy\n"
    "dmVyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGbMA0GCSqGSIb3DQEBAQUAA4GJ\n"
    "ADCBhQJ+AJLOesGugz5aqomDV6wlAXYMra6OLDfO6zV4ZFQD5YRAUcm/jwjiioII\n"
    "0haGN1XpsSECrXZogZoFokvJSyVmIlZsiAeP94FZbYQHZXATcXY+m3dM41CJVphI\n"
    "uR2nKRoTLkoRWZweFdVJVCxzOmmCsZc5nG1wZ0jl3S3WyB57AgMBAAEwDQYJKoZI\n"
    "hvcNAQECBQADfgBl3X7hsuyw4jrg7HFGmhkRuNPHoLQDQCYCPgmc4RKz0Vr2N6W3\n"
    "YQO2WxZpO8ZECAyIUwxrl0nHPjXcbLm7qt9cuzovk2C2qUtN8iD3zV9/ZHuO3ABc\n"
    "1/p3yjkWWW8O6tO1g39NTUJWdrTJXwT4OPjr0l91X817/OWOgHz8UA==\n"
    "-----END CERTIFICATE-----\n",

    // data.mozy.com
    "-----BEGIN CERTIFICATE-----\n"
    "MIICuTCCAiICCQCaFzAD+wqZrzANBgkqhkiG9w0BAQQFADCBoDELMAkGA1UEBhMC\n"
    "VVMxCzAJBgNVBAgTAlVUMRYwFAYDVQQHEw1BbWVyaWNhbiBGb3JrMR4wHAYDVQQK\n"
    "ExVCZXJrZWxleSBEYXRhIFN5c3RlbXMxETAPBgNVBAsTCE1venkuY29tMRYwFAYD\n"
    "VQQDEw1kYXRhLm1venkuY29tMSEwHwYJKoZIhvcNAQkBFhJ3ZWJtYXN0ZXJAbW96\n"
    "eS5jb20wHhcNMDUwOTAyMjAzMDMwWhcNMDUxMDAyMjAzMDMwWjCBoDELMAkGA1UE\n"
    "BhMCVVMxCzAJBgNVBAgTAlVUMRYwFAYDVQQHEw1BbWVyaWNhbiBGb3JrMR4wHAYD\n"
    "VQQKExVCZXJrZWxleSBEYXRhIFN5c3RlbXMxETAPBgNVBAsTCE1venkuY29tMRYw\n"
    "FAYDVQQDEw1kYXRhLm1venkuY29tMSEwHwYJKoZIhvcNAQkBFhJ3ZWJtYXN0ZXJA\n"
    "bW96eS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJo7wqzKP3B3Xn23\n"
    "Rrc61Cj6n7Guopcob6IDlRVp0GmwOsMKU2QRpbtkPUbFgESpBSBKlYYNx6Ul3k6O\n"
    "SXeUvJfB/AzeR+OHbJyBXUbevHLs6O2ouA1pSsaA6Ndn7g7G900ml3bmYUy+952L\n"
    "E6v2CdSTEu8eDdWqvmnFiaucKsl5AgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAjtCL\n"
    "XCbwLiFjjhAn2GAK0ustyc8GZCv+km98CJ7qxxCoS3mF9GRqf4ak7NUstz5o8vEg\n"
    "5cWk8PT2d+ifrAzF8vAZ94Zkq1Ir0/5irM6cLofCJCwpl5MM5VMFVdvlWlNmEM30\n"
    "CAkFggJ5lQ3gg7Rom7o7pt9bvUj3JG95vNJL214=\n"
    "-----END CERTIFICATE-----\n",

    // Berkeley Data Systems CA => data.mozy.com
    "-----BEGIN CERTIFICATE-----\n"
    "MIIE2TCCA8GgAwIBAgIJAPl67JoTbmy5MA0GCSqGSIb3DQEBBQUAMIGjMSEwHwYD\n"
    "VQQDExhCZXJrZWxleSBEYXRhIFN5c3RlbXMgQ0ExCzAJBgNVBAYTAlVTMQ0wCwYD\n"
    "VQQIEwRVdGFoMRYwFAYDVQQHEw1BbWVyaWNhbiBGb3JrMSQwIgYDVQQKExtCZXJr\n"
    "ZWxleSBEYXRhIFN5c3RlbXMsIEluYy4xJDAiBgkqhkiG9w0BCQEWFWNlcnRAYmVy\n"
    "a2VsZXlkYXRhLm5ldDAeFw0wNjA3MTMyMjIyNDNaFw0xMTA3MTIyMjIyNDNaMIGj\n"
    "MSEwHwYDVQQDExhCZXJrZWxleSBEYXRhIFN5c3RlbXMgQ0ExCzAJBgNVBAYTAlVT\n"
    "MQ0wCwYDVQQIEwRVdGFoMRYwFAYDVQQHEw1BbWVyaWNhbiBGb3JrMSQwIgYDVQQK\n"
    "ExtCZXJrZWxleSBEYXRhIFN5c3RlbXMsIEluYy4xJDAiBgkqhkiG9w0BCQEWFWNl\n"
    "cnRAYmVya2VsZXlkYXRhLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
    "ggEBAKzfymB1Qw+uUYSoohx7QAC/vYYByVxvGdOghXjSPu5pWcetOtM3bF+NSSFm\n"
    "w24jrd7fKirIOFziEah1lZer73Noqi1IwyoCtgnbzrOQVTXn3L1yhU4pGw+G/rl9\n"
    "s0IJhwryiUl2gap7kzHve9vZgv71/K0Csb8Fp8baVooOENm3dt+/8uiKDyr8xXut\n"
    "UvVb4hXUGHvULboTAuhBiSgT8h9ut1mX96q5cgroTBbsomZapHM0UWjvPhhPJUbB\n"
    "blYwDy/FOotcx6jEY6bMb5BGXH6uxSCs7F0xV7PAlajyNPyCoKVILBT2FTnlt1vs\n"
    "k9NT9PFIa9k9bOpmY1k8d+YqiAcCAwEAAaOCAQwwggEIMB0GA1UdDgQWBBTXXNk8\n"
    "EzlAOeYJqQ/utd5M7snwWjCB2AYDVR0jBIHQMIHNgBTXXNk8EzlAOeYJqQ/utd5M\n"
    "7snwWqGBqaSBpjCBozEhMB8GA1UEAxMYQmVya2VsZXkgRGF0YSBTeXN0ZW1zIENB\n"
    "MQswCQYDVQQGEwJVUzENMAsGA1UECBMEVXRhaDEWMBQGA1UEBxMNQW1lcmljYW4g\n"
    "Rm9yazEkMCIGA1UEChMbQmVya2VsZXkgRGF0YSBTeXN0ZW1zLCBJbmMuMSQwIgYJ\n"
    "KoZIhvcNAQkBFhVjZXJ0QGJlcmtlbGV5ZGF0YS5uZXSCCQD5euyaE25suTAMBgNV\n"
    "HRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQCfDGMWzWBpoUsok+kioRpgJXXF\n"
    "uWerXRIyh+9gNbprmuEbJVuEv1J/BedSumUh6hNx9gJpl4NuxmNUA99SqrtxwKea\n"
    "YjGpJ3DkqVx4SVgcL6hifD4s/6ffQITUJHnjSswhRnnkSxwj6ujPqGo22rNA8kuk\n"
    "rzW2m76VmOMec5sQYov2faJolv+DqZCDMJAll2Q0+BJI4frEda6v5KhxKwYku85O\n"
    "cdv/v2tYa3mMTRJKsl2gFHsbNVqVdg0J4MXluW1tCPaGWZ45fAQFvV0ccWVlJvNC\n"
    "JE+XXCl1oGnrpBSxjJt47FZnsuSlSegPEFJPB6fPNzCeL/BKSTQJLc+DMUlv\n"
    "-----END CERTIFICATE-----\n",

    // RapidSSL => *.decho.cn
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDIDCCAomgAwIBAgIENd70zzANBgkqhkiG9w0BAQUFADBOMQswCQYDVQQGEwJV\n"
    "UzEQMA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2Vy\n"
    "dGlmaWNhdGUgQXV0aG9yaXR5MB4XDTk4MDgyMjE2NDE1MVoXDTE4MDgyMjE2NDE1\n"
    "MVowTjELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0VxdWlmYXgxLTArBgNVBAsTJEVx\n"
    "dWlmYXggU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eTCBnzANBgkqhkiG9w0B\n"
    "AQEFAAOBjQAwgYkCgYEAwV2xWGcIYu6gmi0fCG2RFGiYCh7+2gRvE4RiIcPRfM6f\n"
    "BeC4AfBONOziipUEZKzxa1NfBbPLZ4C/QgKO/t0BCezhABRP/PvwDN1Dulsr4R+A\n"
    "cJkVV5MW8Q+XarfCaCMczE1ZMKxRHjuvK9buY0V7xdlfUNLjUA86iOe/FP3gx7kC\n"
    "AwEAAaOCAQkwggEFMHAGA1UdHwRpMGcwZaBjoGGkXzBdMQswCQYDVQQGEwJVUzEQ\n"
    "MA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2VydGlm\n"
    "aWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMBoGA1UdEAQTMBGBDzIwMTgw\n"
    "ODIyMTY0MTUxWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gj\n"
    "IBBPM5iQn9QwHQYDVR0OBBYEFEjmaPkr0rKV10fYIyAQTzOYkJ/UMAwGA1UdEwQF\n"
    "MAMBAf8wGgYJKoZIhvZ9B0EABA0wCxsFVjMuMGMDAgbAMA0GCSqGSIb3DQEBBQUA\n"
    "A4GBAFjOKer89961zgK5F7WF0bnj4JXMJTENAKaSbn+2kmOeUJXRmm/kEd5jhW6Y\n"
    "7qj/WsjTVbJmcVfewCHrPSqnI0kBBIZCe/zuf6IWUrVnZ9NA2zsmWLIodz2uFHdh\n"
    "1voqZiegDfqnc1zqcPGUIWVEX/r87yloqaKHee9570+sB3c4\n"
    "-----END CERTIFICATE-----\n",

    // RSA Intermediate Certificates
    "-----BEGIN CERTIFICATE-----\n"
    "MIID0jCCAzugAwIBAgIQMtiYN2/kRcIfkfW5f44LsDANBgkqhkiG9w0BAQUFADCB\n"
    "gjEaMBgGA1UEChMRUlNBIFNlY3VyaXR5IEluYy4xFTATBgNVBAsTDEtDQSBTZXJ2\n"
    "aWNlczEWMBQGA1UEAxMNUlNBIENvcnBvcmF0ZTEQMA4GA1UEBxMHQmVkZm9yZDEW\n"
    "MBQGA1UECBMNTWFzc2FjaHVzZXR0czELMAkGA1UEBhMCVVMwHhcNMDcwNTEwMjEz\n"
    "ODMzWhcNMTIwMzMwMDkzMDM5WjCBjDEaMBgGA1UEChMRUlNBIFNlY3VyaXR5IElu\n"
    "Yy4xFTATBgNVBAsTDEtDQSBTZXJ2aWNlczEgMB4GA1UEAxMXUlNBIENvcnBvcmF0\n"
    "ZSBTZXJ2ZXIgQ0ExEDAOBgNVBAcTB0JlZGZvcmQxFjAUBgNVBAgTDU1hc3NhY2h1\n"
    "c2V0dHMxCzAJBgNVBAYTAlVTMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCy\n"
    "djJ4OfEVXqGAiOL+asMi87XQqNbjOtGrNckPyOLlRPosgtC6mA8PC8QkX+u98NxF\n"
    "RtPAppXQQQixO0/zyK0HLJolSVnv+2gXy85mbkJ2knY3r6ehmizrU/mo1Rm3+YsC\n"
    "gNQKJuISDWnm07XTcDSC6rUvOzfzSsOfrT+mynbjmwIDAQABo4IBOzCCATcwDwYD\n"
    "VR0TBAgwBgEB/wIBAjCBkgYDVR0gBIGKMIGHMIGEBgkqhkiG9w0FBwIwdzAuBggr\n"
    "BgEFBQcCARYiaHR0cDovL2NhLnJzYXNlY3VyaXR5LmNvbS9DUFMuaHRtbDBFBggr\n"
    "BgEFBQcCAjA5MBgWEVJTQSBTZWN1cml0eSBJbmMuMAMCAQEaHUNQUyBJbmNvcnBv\n"
    "cmF0ZWQgYnkgcmVmZXJlbmNlMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwu\n"
    "cnNhc2VjdXJpdHkuY29tL1JTQSUyMENvcnBvcmF0ZS5jcmwwDgYDVR0PAQH/BAQD\n"
    "AgGGMB8GA1UdIwQYMBaAFO2RCGt0t1lKkvahHSJwJp8KrxaSMB0GA1UdDgQWBBSJ\n"
    "z061oIdefkN40ZlJaAd8hAczVjANBgkqhkiG9w0BAQUFAAOBgQAlM3KPKLfUR7jk\n"
    "sVNPX7FIda9IZItLQo5A70+dEFjDGooPSZvU10li8GiBBAaoZPUh9R4lGf++bvGh\n"
    "O7EALax8srwCSGwIkAzVyylAYiOVFrrdhhIgvzyXUVnmkB9Yf75HbXwxUoTYTSq/\n"
    "h48CeK/KpCDcDZT795RJkwChJN27VA==\n"
    "-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDSjCCArOgAwIBAgIRAIXStR6BlvxLY6PPtrJYs3wwDQYJKoZIhvcNAQEFBQAw\n"
    "bDEaMBgGA1UEChMRUlNBIFNlY3VyaXR5IEluYy4xHjAcBgNVBAMTFVJTQSBQdWJs\n"
    "aWMgUm9vdCBDQSB2MTEuMCwGCSqGSIb3DQEJARYfcnNha2VvbnJvb3RzaWduQHJz\n"
    "YXNlY3VyaXR5LmNvbTAeFw0wNzA0MTkxODAyMTlaFw0xMjA0MzAwOTI4MDdaMIGC\n"
    "MRowGAYDVQQKExFSU0EgU2VjdXJpdHkgSW5jLjEVMBMGA1UECxMMS0NBIFNlcnZp\n"
    "Y2VzMRYwFAYDVQQDEw1SU0EgQ29ycG9yYXRlMRAwDgYDVQQHEwdCZWRmb3JkMRYw\n"
    "FAYDVQQIEw1NYXNzYWNodXNldHRzMQswCQYDVQQGEwJVUzCBnzANBgkqhkiG9w0B\n"
    "AQEFAAOBjQAwgYkCgYEAqnOw876lPpMTkSqrqzpEON/609PDLEhmWX4tkC19AHne\n"
    "DaoetL277GtYYXBCggP2E+s66MN1ccWXyApfWjCZkIHepPC08NVI1JRcbViW3kwL\n"
    "zDD2w5T9QJcyL5V1pN/LQdxahM56TiLeXlPiJekdmTdJoo+5Pw4bQU+MxTqURk8C\n"
    "AwEAAaOB1DCB0TAfBgNVHSMEGDAWgBT1TDF6UQM/LNeLl5lvqHGQq3g9mzAdBgNV\n"
    "HQ4EFgQU7ZEIa3S3WUqS9qEdInAmnwqvFpIwbgYDVR0fBGcwZTBjoGGgX4ZdaHR0\n"
    "cDovL3d3dy5yc2FzZWN1cml0eS5jb20vcHJvZHVjdHMva2Vvbi9yZXBvc2l0b3J5\n"
    "L2NlcnRpZmljYXRlX3N0YXR1cy9SU0FfUHVibGljX1Jvb3RfQ0EuY3JsMA8GA1Ud\n"
    "EwQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAH6l\n"
    "rogybtlsuxYM4mfEfzOGJiy4hM1B4scXozUPo8zlzjUkB5gmEOiKyYKsVFSLJz/N\n"
    "7GC0+iUIfUyJtXavKi0PrJFOf4STKOe5M0Ng205KrmwuclZe8A70fUnZRBUYJI+U\n"
    "XWiFHSZyCLNKdjKNYW05B4b1b6P27aqG7RjZGQl1\n"
    "-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDdDCCAt2gAwIBAgIQJyzRkL6Balz4Y8X3iFwiFjANBgkqhkiG9w0BAQUFADCB\n"
    "uzEkMCIGA1UEBxMbVmFsaUNlcnQgVmFsaWRhdGlvbiBOZXR3b3JrMRcwFQYDVQQK\n"
    "Ew5WYWxpQ2VydCwgSW5jLjE1MDMGA1UECxMsVmFsaUNlcnQgQ2xhc3MgMyBQb2xp\n"
    "Y3kgVmFsaWRhdGlvbiBBdXRob3JpdHkxITAfBgNVBAMTGGh0dHA6Ly93d3cudmFs\n"
    "aWNlcnQuY29tLzEgMB4GCSqGSIb3DQEJARYRaW5mb0B2YWxpY2VydC5jb20wHhcN\n"
    "MDUwNTAyMTczNDQ4WhcNMTkwNDMwMDkyNDAwWjBsMRowGAYDVQQKExFSU0EgU2Vj\n"
    "dXJpdHkgSW5jLjEeMBwGA1UEAxMVUlNBIFB1YmxpYyBSb290IENBIHYxMS4wLAYJ\n"
    "KoZIhvcNAQkBFh9yc2FrZW9ucm9vdHNpZ25AcnNhc2VjdXJpdHkuY29tMIGfMA0G\n"
    "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0dSVa2EQ740GxqiIKsHATT4f8XYwUU23p\n"
    "zRe5W6IVpt4jkwDWkgnvTcP6M8PD4OfK6Imal4hAH/c3K/dUIH7YyQZRGAE5Y27G\n"
    "5klZYKidcFlrfautgVES170MLKFmJqym2FWAfVOibXatRcw7B0S+mP9404jID/Ma\n"
    "IpRXkH5JjwIDAQABo4HGMIHDMB0GA1UdDgQWBBT1TDF6UQM/LNeLl5lvqHGQq3g9\n"
    "mzBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3LnJzYXNlY3VyaXR5LmNvbS9w\n"
    "cm9kdWN0cy9rZW9uL3JlcG9zaXRvcnkvY2VydGlmaWNhdGVfc3RhdHVzL1ZhbGlj\n"
    "ZXJ0X1Jvb3RfQ0EuY3JsMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMBYG\n"
    "A1UdIAQPMA0wCwYJKoZIhvcNBQYBMA0GCSqGSIb3DQEBBQUAA4GBAJsZWGBPVGmc\n"
    "xmwH5vM9xqt6r1jjQE44zOFNgwlXp0YR605ss5SjkVlyx4WtjKzSrI4hPLhVJN5f\n"
    "69F7NxNQMf658Mkkx3Vv6+orEvHFqIw/Hx4uqmdBRpHy/cckaBcEqhJfew7IUFS+\n"
    "4KRrACEZFnBeaZQlTH8J7UqTThT7By2x\n"
    "-----END CERTIFICATE-----\n",

    //DigiCert High Assurance EV Root CA => DigiCert High Assurance CA-3
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGWDCCBUCgAwIBAgIQCl8RTQNbF5EX0u/UA4w/OzANBgkqhkiG9w0BAQUFADBs\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
    "d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"
    "ZSBFViBSb290IENBMB4XDTA4MDQwMjEyMDAwMFoXDTIyMDQwMzAwMDAwMFowZjEL\n"
    "MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\n"
    "LmRpZ2ljZXJ0LmNvbTElMCMGA1UEAxMcRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug\n"
    "Q0EtMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9hCikQH17+NDdR\n"
    "CPge+yLtYb4LDXBMUGMmdRW5QYiXtvCgFbsIYOBC6AUpEIc2iihlqO8xB3RtNpcv\n"
    "KEZmBMcqeSZ6mdWOw21PoF6tvD2Rwll7XjZswFPPAAgyPhBkWBATaccM7pxCUQD5\n"
    "BUTuJM56H+2MEb0SqPMV9Bx6MWkBG6fmXcCabH4JnudSREoQOiPkm7YDr6ictFuf\n"
    "1EutkozOtREqqjcYjbTCuNhcBoz4/yO9NV7UfD5+gw6RlgWYw7If48hl66l7XaAs\n"
    "zPw82W3tzPpLQ4zJ1LilYRyyQLYoEt+5+F/+07LJ7z20Hkt8HEyZNp496+ynaF4d\n"
    "32duXvsCAwEAAaOCAvowggL2MA4GA1UdDwEB/wQEAwIBhjCCAcYGA1UdIASCAb0w\n"
    "ggG5MIIBtQYLYIZIAYb9bAEDAAIwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3\n"
    "LmRpZ2ljZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUH\n"
    "AgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQBy\n"
    "AHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBj\n"
    "AGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAg\n"
    "AEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQ\n"
    "AGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBt\n"
    "AGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBj\n"
    "AG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBl\n"
    "AHIAZQBuAGMAZQAuMBIGA1UdEwEB/wQIMAYBAf8CAQAwNAYIKwYBBQUHAQEEKDAm\n"
    "MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wgY8GA1UdHwSB\n"
    "hzCBhDBAoD6gPIY6aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGln\n"
    "aEFzc3VyYW5jZUVWUm9vdENBLmNybDBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNl\n"
    "cnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDAfBgNVHSME\n"
    "GDAWgBSxPsNpA/i/RwHUmCYaCALvY2QrwzAdBgNVHQ4EFgQUUOpzidsp+xCPnuUB\n"
    "INTeeZlIg/cwDQYJKoZIhvcNAQEFBQADggEBAB7ipUiebNtTOA/vphoqrOIDQ+2a\n"
    "vD6OdRvw/S4iWawTwGHi5/rpmc2HCXVUKL9GYNy+USyS8xuRfDEIcOI3ucFbqL2j\n"
    "CwD7GhX9A61YasXHJJlIR0YxHpLvtF9ONMeQvzHB+LGEhtCcAarfilYGzjrpDq6X\n"
    "dF3XcZpCdF/ejUN83ulV7WkAywXgemFhM9EZTfkI7qA5xSU1tyvED7Ld8aW3DiTE\n"
    "JiiNeXf1L/BXunwH1OH8zVowV36GEEfdMR/X/KLCvzB8XSSq6PmuX2p0ws5rs0bY\n"
    "Ib4p1I5eFdZCSucyb6Sxa1GDWL4/bcf72gMhy2oWGU4K8K2Eyl2Us1p292E=\n"
    "-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
    "d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"
    "ZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL\n"
    "MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\n"
    "LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug\n"
    "RVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm\n"
    "+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW\n"
    "PNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEM\n"
    "xChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB\n"
    "Ik5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3\n"
    "hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg\n"
    "EsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF\n"
    "MAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA\n"
    "FLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec\n"
    "nzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6z\n"
    "eM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF\n"
    "hS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2\n"
    "Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe\n"
    "vEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep\n"
    "+OkuE6N36B9K\n"
    "-----END CERTIFICATE-----\n"
};

#include "logger.h"
REGISTER_LOGGER("dpc:connector:ssl_serts");

namespace dpc
{

int LoadAppCertificates(X509_STORE *app_store)
{
    size_t numCerts = sizeof(sslCertificates) / sizeof(sslCertificates[0]);
    for(size_t i = 0; i < numCerts; ++i) {
        X509 *cert = NULL;
        BIO *bio = BIO_new_mem_buf((void *)sslCertificates[i], -1);
        if (!PEM_read_bio_X509(bio, &cert, NULL, (void *)"" /* no password */)) {
            MORDOR_LOG_WARNING(g_log) << "Read local certificates failed.";
        }else if (!X509_STORE_add_cert(app_store, cert)) {
            MORDOR_LOG_WARNING(g_log) << "Add local certificates failed.";
        }
        X509_free(cert);
        BIO_free(bio);
    }

    return numCerts;
}
} //dpc namespace