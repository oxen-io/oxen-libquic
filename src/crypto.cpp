#include "connection.hpp"
#include "client.hpp"
#include "crypto.hpp"
#include <gnutls/gnutls.h>


namespace oxen::quic
{
    //



    int
    TLSCertManager::gnutls_config(Connection &c)
    {
        int rv = gnutls_certificate_allocate_credentials(&cred);

        return 0;
    }

}   // namespace oxen::quic
